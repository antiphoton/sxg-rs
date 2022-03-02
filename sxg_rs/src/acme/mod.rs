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

//! ACME(Automatic Certificate Management Environment) is defined in [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555).

mod client;
mod directory;
mod jose;

use crate::crypto::EcPublicKey;
use crate::fetcher::Fetcher;
use crate::signature::Signer;
use anyhow::Result;
use client::Client;

pub async fn get_cert<F: Fetcher, S: Signer>(
    directory_url: &str,
    public_key: EcPublicKey,
    fetcher: &F,
    signer: &S,
) -> Result<()> {
    let mut client = Client::new(directory_url, public_key, fetcher).await?;
    let account_url = client
        .get_account_url("foo@bar.com", fetcher, signer)
        .await?;
    client
        .apply_certificate(&account_url, "bar.com".to_string(), fetcher, signer)
        .await?;
    Ok(())
}

pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    static X: Lazy<Vec<u8>> =
        Lazy::new(|| base64::decode("bvhfVoqrJ8FomDZa9MhfTY4NSP13FtpcjOvmX+mA47c=").unwrap());
    static Y: Lazy<Vec<u8>> =
        Lazy::new(|| base64::decode("tZ+8QKYXIfnl7j9pMylyhCNKiT2p6yFnoVts28bxEVo=").unwrap());
    static D: Lazy<Vec<u8>> =
        Lazy::new(|| base64::decode("A+qJRPq/kvk+L9ijVFCHw3hMBQ6lc8JjF7lkTp+ndGQ=").unwrap());
    #[test]
    fn sxg_rs() {
        use super::*;
        tokio_test::block_on(async {
            let fetcher = crate::fetcher::hyper_fetcher::HyperFetcher::new();
            let signer = crate::signature::rust_signer::RustSigner::new(&D).unwrap();
            let public_key = EcPublicKey {
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x: X.clone(),
                y: Y.clone(),
            };
            get_cert(LETSENCRYPT_STAGING, public_key, &fetcher, &signer)
                .await
                .unwrap();
            // panic!();
        });
    }
}
