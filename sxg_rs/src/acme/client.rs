// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::directory::{
    Authorization, Challenge, Directory, FinalizeRequest, Identifier, IdentifierType,
    NewAccountRequestPayload, NewAccountResponsePayload, NewOrderRequestPayload, Order, Status,
};
use super::jose::EcPublicKey;
use crate::fetcher::Fetcher;
use crate::http::{HttpRequest, HttpResponse, Method};
use crate::signature::Signer;
use anyhow::{anyhow, Error, Result};
use serde::Serialize;
use std::sync::Arc;
use warp::Filter;

pub struct Client {
    public_key: EcPublicKey,
    directory: Directory,
    nonce: Option<String>,
}

#[derive(PartialEq, Eq)]
enum AuthMethod<'a> {
    JsonWebKey,
    KeyId(&'a str),
}

impl Client {
    pub async fn new<F: Fetcher>(
        directory_url: &str,
        public_key_x: Vec<u8>,
        public_key_y: Vec<u8>,
        fetcher: &F,
    ) -> Result<Self> {
        let directory = Directory::new(directory_url, fetcher).await?;
        let public_key = EcPublicKey::new("P-256", public_key_x, public_key_y);
        Ok(Client {
            public_key,
            directory,
            nonce: None,
        })
    }
    pub async fn get_account_url<F: Fetcher, S: Signer>(
        &mut self,
        email: &str,
        fetcher: &F,
        signer: &S,
    ) -> Result<String> {
        let req_payload = NewAccountRequestPayload {
            contact: vec![format!("mailto:{}", email)],
            terms_of_service_agreed: true, // DO NOT SUBMIT
        };
        let response = self
            .post_with_payload(
                AuthMethod::JsonWebKey,
                self.directory.new_account.clone(),
                req_payload,
                fetcher,
                signer,
            )
            .await?;
        let account_url = find_header(&response, "Location")?;
        let rsp_paylod: NewAccountResponsePayload = serde_json::from_slice(&response.body)
            .map_err(|e| Error::new(e).context("Failed to parse new account response"))?;
        if rsp_paylod.status != Status::Valid {
            return Err(Error::msg("The account status is not valid"));
        }
        Ok(account_url)
    }
    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
    pub async fn apply_certificate<F: Fetcher, S: Signer>(
        &mut self,
        account_url: &str,
        domain: String,
        csr_der: &[u8],
        fetcher: &F,
        signer: &S,
    ) -> Result<()> {
        let req_payload = NewOrderRequestPayload {
            identifiers: vec![Identifier {
                r#type: IdentifierType::Dns,
                value: domain,
            }],
            not_before: None,
            not_after: None,
        };
        let order = self
            .post_with_payload(
                AuthMethod::KeyId(account_url),
                self.directory.new_order.clone(),
                req_payload,
                fetcher,
                signer,
            )
            .await?;
        let order: Order = serde_json::from_slice(&order.body)
            .map_err(|e| Error::new(e).context("Failed to parse new order response"))?;
        let authorization_url = order
            .authorizations
            .into_iter()
            .next()
            .ok_or_else(|| Error::msg("The order response does not contain authorizations"))?;
        let authorization = self
            .post_as_get(
                AuthMethod::KeyId(account_url),
                authorization_url,
                fetcher,
                signer,
            )
            .await?;
        let authorization: Authorization = serde_json::from_slice(&authorization.body)
            .map_err(|e| Error::new(e).context("Failed to parse authorization response"))?;
        let challenge = authorization
            .challenges
            .into_iter()
            .find_map(|challenge| {
                if challenge.r#type == "http-01" {
                    Some(challenge)
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::msg("The authorization does not have http-01 type challenge"))?;
        // https://datatracker.ietf.org/doc/html/rfc8555#section-8.1
        let challenge_answer = Arc::new(format!(
            "{}.{}",
            challenge.token,
            base64::encode_config(self.public_key.get_thumbprint(), base64::URL_SAFE_NO_PAD)
        ));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let routes = warp::path!(".well-known" / "acme-challenge" / String)
            .map(move |name| format!("{}", challenge_answer));
        let (_addr, server) =
            warp::serve(routes).bind_with_graceful_shutdown(([127, 0, 0, 1], 8002), async {
                rx.await.ok();
            });
        tokio::spawn(server);
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        // https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.1
        // The client indicates to the server that it is ready for the challenge
        // validation by sending an empty JSON body ("{}") carried in a POST
        // request to the challenge URL (not the authorization URL).
        self.post_with_payload(
            AuthMethod::KeyId(account_url),
            challenge.url.clone(),
            serde_json::Map::new(),
            fetcher,
            signer,
        )
        .await?;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let _ = tx.send(());
        let asdf = self
            .post_with_payload(
                AuthMethod::KeyId(account_url),
                order.finalize.clone(),
                FinalizeRequest {
                    csr: &base64::encode_config(csr_der, base64::URL_SAFE_NO_PAD),
                },
                fetcher,
                signer,
            )
            .await?;

        Ok(())
    }
}

impl Client {
    async fn post_as_get<F: Fetcher, S: Signer>(
        &mut self,
        auth_method: AuthMethod<'_>,
        url: String,
        fetcher: &F,
        signer: &S,
    ) -> Result<HttpResponse> {
        let payload: Option<()> = None;
        self.post_impl(auth_method, url, payload, fetcher, signer)
            .await
    }
    async fn post_with_payload<F: Fetcher, S: Signer, P: Serialize>(
        &mut self,
        auth_method: AuthMethod<'_>,
        url: String,
        payload: P,
        fetcher: &F,
        signer: &S,
    ) -> Result<HttpResponse> {
        self.post_impl(auth_method, url, Some(payload), fetcher, signer)
            .await
    }
    async fn post_impl<F: Fetcher, S: Signer, P: Serialize>(
        &mut self,
        auth_method: AuthMethod<'_>,
        url: String,
        payload: Option<P>,
        fetcher: &F,
        signer: &S,
    ) -> Result<HttpResponse> {
        let nonce = self.take_nonce(fetcher).await?;
        let (jwk, key_id) = match auth_method {
            AuthMethod::JsonWebKey => (Some(&self.public_key), None),
            AuthMethod::KeyId(key_id) => (None, Some(key_id)),
        };
        let request_body =
            super::jose::create_request_body(jwk, key_id, nonce, &url, payload, signer).await?;
        let request = HttpRequest {
            url: url.clone(),
            method: Method::Post,
            headers: vec![(
                "content-type".to_string(),
                "application/jose+json".to_string(),
            )],
            body: request_body,
        };
        let response = fetcher.fetch(request).await?;
        println!(
            "POST {}\n{}\n",
            url,
            String::from_utf8(response.body.clone()).unwrap()
        );
        if let Ok(nonce) = find_header(&response, "Replay-Nonce") {
            let _ = self.nonce.insert(nonce);
        }
        Ok(response)
    }
    async fn take_nonce<F: Fetcher>(&mut self, fetcher: &F) -> Result<String> {
        match self.nonce.take() {
            Some(nonce) => Ok(nonce),
            None => self.fetch_new_nonce(fetcher).await,
        }
    }
    async fn fetch_new_nonce<F: Fetcher>(&self, fetcher: &F) -> Result<String> {
        let request = HttpRequest {
            method: Method::Get,
            headers: vec![],
            url: self.directory.new_nonce.clone(),
            body: vec![],
        };
        let response = fetcher.fetch(request).await?;
        find_header(&response, "Replay-Nonce")
    }
}

fn find_header(response: &HttpResponse, header_name: &str) -> Result<String> {
    response
        .headers
        .iter()
        .find_map(|(name, value)| {
            if name.eq_ignore_ascii_case(header_name) {
                Some(value.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("The response header does not contain {}", header_name))
}
