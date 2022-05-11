// Copyright 2022 Google LLC
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

use anyhow::{Error, Result};
use clap::Parser;
use warp::Filter;

use crate::linux_commands::{create_certificate_request_pem, read_or_create_private_key_pem};
use crate::runtime::hyper_fetcher::HyperFetcher;
use serde::{Deserialize, Serialize};
use sxg_rs::acme::directory::Directory;
use sxg_rs::acme::eab::create_external_account_binding;
use sxg_rs::acme::jws::JsonWebSignature;
use sxg_rs::crypto::{EcPrivateKey, EcPublicKey};
use sxg_rs::fetcher::Fetcher;

#[derive(Debug, Parser)]
#[clap(allow_hyphen_values = true)]
pub struct Opts {
    #[clap(long)]
    port: u16,
    /// Directory URL of ACME server
    #[clap(long)]
    acme_server: String,
    #[clap(long)]
    email: String,
    #[clap(long)]
    domain: String,
    #[clap(long, default_value_t=String::from("acme_account_private_key.pem"))]
    acme_account_private_key_file: String,
    #[clap(long, default_value_t=String::from("privkey.pem"))]
    sxg_private_key_file: String,
    #[clap(long, default_value_t=String::from("cert.csr"))]
    sxg_cert_request_file: String,
    #[clap(long)]
    agreed_terms_of_service: String,
    #[clap(long)]
    eab_mac_key: Option<String>,
    #[clap(long)]
    eab_key_id: Option<String>,
}

fn start_warp_server(port: u16, answer: String) -> tokio::sync::oneshot::Sender<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let routes =
        warp::path!(".well-known" / "acme-challenge" / String).map(move |_name| answer.to_string());
    let (_addr, server) =
        warp::serve(routes).bind_with_graceful_shutdown(([127, 0, 0, 1], port), async {
            rx.await.ok();
        });
    tokio::spawn(server);
    tx
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EabParams {
    pub base64_mac_key: String,
    pub key_id: String,
}

impl EabParams {
    pub async fn create_signature(
        &self,
        acme_public_key: &EcPublicKey,
        server_url: &str,
        fetcher: &dyn Fetcher,
    ) -> Result<JsonWebSignature> {
        let mac_key = base64::decode_config(&self.base64_mac_key, base64::URL_SAFE_NO_PAD)?;
        let eab_signer = crate::runtime::openssl_signer::OpensslSigner::Hmac(&mac_key);
        let new_account_url = Directory::from_url(server_url, fetcher)
            .await?
            .0
            .new_account;
        create_external_account_binding(
            sxg_rs::acme::jws::Algorithm::HS256,
            &self.key_id,
            &new_account_url,
            &acme_public_key,
            &eab_signer,
        )
        .await
    }
}

pub async fn main(opts: Opts) -> Result<()> {
    let acme_private_key = {
        let private_key_pem = read_or_create_private_key_pem(&opts.acme_account_private_key_file)?;
        EcPrivateKey::from_sec1_pem(&private_key_pem)?
    };
    let sxg_cert_request_der = {
        read_or_create_private_key_pem(&opts.sxg_private_key_file)?;
        let cert_request_pem = create_certificate_request_pem(
            &opts.domain,
            &opts.sxg_private_key_file,
            &opts.sxg_cert_request_file,
        )?;
        sxg_rs::crypto::get_der_from_pem(&cert_request_pem, "CERTIFICATE REQUEST")?
    };
    let runtime = sxg_rs::runtime::Runtime {
        acme_signer: Box::new(acme_private_key.create_signer()?),
        fetcher: Box::new(HyperFetcher::new()),
        ..Default::default()
    };
    let external_account_binding = match (opts.eab_key_id, opts.eab_mac_key) {
        (Some(eab_key_id), Some(eab_mac_key)) => {
            let eab_params = EabParams {
                base64_mac_key: eab_mac_key,
                key_id: eab_key_id,
            };
            Some(
                eab_params
                    .create_signature(
                        &acme_private_key.public_key,
                        &opts.acme_server,
                        runtime.fetcher.as_ref(),
                    )
                    .await?,
            )
        }
        (None, None) => None,
        _ => {
            return Err(Error::msg(
                "To use External Account Binding, \
                please provide both \"eab-key-id\" and \"eab-mac-key\".",
            ))
        }
    };
    let acme_account = sxg_rs::acme::create_account(
        sxg_rs::acme::AccountSetupParams {
            directory_url: opts.acme_server.clone(),
            agreed_terms_of_service: &opts.agreed_terms_of_service,
            external_account_binding,
            email: &opts.email,
            domain: opts.domain.clone(),
            public_key: acme_private_key.public_key,
            cert_request_der: sxg_cert_request_der,
        },
        runtime.fetcher.as_ref(),
        runtime.acme_signer.as_ref(),
    )
    .await?;
    let ongoing_certificate_request = sxg_rs::acme::place_new_order(
        &acme_account,
        runtime.fetcher.as_ref(),
        runtime.acme_signer.as_ref(),
    )
    .await?;
    let tx = start_warp_server(
        opts.port,
        ongoing_certificate_request.challenge_answer.clone(),
    );
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let certificate_pem = sxg_rs::acme::continue_challenge_validation_and_get_certificate(
        &acme_account,
        ongoing_certificate_request,
        runtime.fetcher.as_ref(),
        runtime.acme_signer.as_ref(),
    )
    .await?;
    let _ = tx.send(());
    println!("{}", certificate_pem);
    Ok(())
}
