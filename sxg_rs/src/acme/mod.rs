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

#[cfg(target_family = "unix")]
pub mod cli;
mod client;
mod directory;
mod jose;

use crate::fetcher::Fetcher;
use crate::signature::Signer;
use anyhow::Result;
use client::Client;

// https://datatracker.ietf.org/doc/html/rfc8555#:~:text=The%20following%20table%20illustrates%20a%20typical%20sequence
pub async fn get_cert<F: Fetcher, S: Signer>(
    directory_url: &str,
    public_key_x: Vec<u8>,
    public_key_y: Vec<u8>,
    csr_der: &[u8],
    fetcher: &F,
    signer: &S,
) -> Result<()> {
    let mut client = Client::new(directory_url, public_key_x, public_key_y, fetcher).await?;
    let account_url = client
        .get_account_url("caoboxiao@google.com", fetcher, signer)
        .await?;
    client
        .apply_certificate(
            &account_url,
            "caoboxiao.com".to_string(),
            csr_der,
            fetcher,
            signer,
        )
        .await?;
    Ok(())
}

pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
