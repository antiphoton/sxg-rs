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

use std::io::Error as IoError;

use serde::{Deserialize, Serialize};
use sxg_rs::config::ConfigInput as SxgInput;

#[derive(Deserialize)]
pub struct FastlyInput {
    service_id: String,
    private_key_base64: String,
}

#[derive(Serialize)]
struct FastlyOutput {
    language: String,
    manifest_version: u8,
    name: String,
    service_id: String,
}

fn validate_private_key_base64(s: &str) -> () {
    let bytes = base64::decode(s).expect(r#"Unable to parse "private_key_base64""#);
    if bytes.len() != 32 {
        panic!("The private key it not 32 bytes");
    }
}

pub fn run(mut sxg_input: SxgInput, fastly_input: FastlyInput) -> Result<(), IoError> {
    let output = FastlyOutput {
        language: "rust".to_string(),
        manifest_version: 1,
        name: "sxg-rs".to_string(),
        service_id: fastly_input.service_id,
    };
    validate_private_key_base64(&fastly_input.private_key_base64);
    assert!(
        sxg_input.private_key_base64.is_none(),
        r#"Pleaes leave "sxg.private_key_base64" empty, and put the value into "fastly.private_key_base64"."#
    );
    sxg_input.private_key_base64 = Some(fastly_input.private_key_base64);
    crate::utils::write_generated_file(
        "fastly_compute/config.yaml",
        &serde_yaml::to_string(&sxg_input).unwrap(),
    )?;
    crate::utils::write_generated_file(
        "fastly_compute/fastly.toml",
        &toml::to_string_pretty(&output).unwrap(),
    )?;
    Ok(())
}
