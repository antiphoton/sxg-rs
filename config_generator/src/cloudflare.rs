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
//

use anyhow::{Result};
use serde::{Deserialize, Serialize};
use sxg_rs::config::ConfigInput as SxgInput;
use wrangler::settings::global_user::GlobalUser;
use wrangler::settings::toml::ConfigKvNamespace;

#[derive(Deserialize, Serialize)]
pub struct CloudflareInput {
    account_id: String,
    zone_id: String,
    routes: Vec<String>,
    off_path_mode: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct Vars {
    html_host: String,
    sxg_config: String,
    #[serde(default)]
    cert_pem: String,
    #[serde(default)]
    issuer_pem: String,
}

// TODO: Use `wrangler::settings::toml::Manifest`
// after [this PR](https://github.com/cloudflare/wrangler/issues/2085)
// goes live in wrangler release version.
#[derive(Deserialize, Serialize)]
struct WranglerOutput {
    name: String,
    #[serde(rename = "type")]
    target_type: String,
    account_id: String,
    zone_id: String,
    routes: Vec<String>,
    workers_dev: Option<bool>,
    kv_namespaces: Vec<ConfigKvNamespace>,
    vars: Vars,
}

// Get the Cloudflare user.
// If there is no active user, the terminal will display a login link.
// This function will wait for the login process before returning.
fn get_global_user() -> Option<GlobalUser> {
    println!("Checking Cloudflare login state");
    let mut user = GlobalUser::new();
    if user.is_err() {
        if std::env::var("CI").is_ok() {
            println!(r#"Using no-login mode in CI environments."#);
            return None;
        }
        wrangler::login::run(None).unwrap();
        user = GlobalUser::new();
    }
    println!("Successfully login to Cloudflare");
    user.ok()
}

// Get the ID of the KV namespace for OCSP.
// If there is no such KV namespace, one will be created.
fn get_ocsp_kv_id(user: &GlobalUser, account_id: &str) -> String {
    let client = wrangler::http::cf_v4_client(user).unwrap();
    let target: wrangler::settings::toml::Target = Default::default();
    let namespaces = wrangler::kv::namespace::list(&client, &target).unwrap();
    if let Some(namespace) = namespaces.into_iter().find(|n| n.title == "sxg-OCSP") {
        return namespace.id;
    }
    let namespace = wrangler::kv::namespace::create(&client, account_id, "OCSP")
        .unwrap()
        .result;
    namespace.id
}

pub fn run(
    credentials: super::SxgCredentials,
    sxg_input: SxgInput,
    cloudflare_input: CloudflareInput,
) -> Result<()> {
    let user = get_global_user();
    let ocsp_kv_id = if let Some(user) = user {
        get_ocsp_kv_id(&user, &cloudflare_input.account_id)
    } else {
        "OSCP_KV_ID_PLACEHOLDER".to_string()
    };
    let ocsp_kv_namespace = ConfigKvNamespace {
        binding: String::from("OCSP"),
        preview_id: Some(ocsp_kv_id.clone()),
        id: Some(ocsp_kv_id),
    };
    let mut routes = cloudflare_input.routes;
    routes.append(format!(
        "{}/{}/*",
        sxg_input.html_host, sxg_input.reserved_path
    ));
    routes.append(format!(
        "{}/{}/*",
        sxg_input.html_host, sxg_input.cert_url_dirname
    ));
    routes.append(format!(
        "{}/{}/*",
        sxg_input.html_host, sxg_input.validity_url_dirname
    ));
    let output = WranglerOutput {
        name: "sxg".to_string(),
        target_type: "rust".to_string(),
        account_id: cloudflare_input.account_id,
        zone_id: cloudflare_input.zone_id,
        kv_namespaces: vec![ocsp_kv_namespace],
        workers_dev: Some(true),
        routes,
        vars: Vars {
            cert_pem: credentials.cert_pem,
            issuer_pem: credentials.issuer_pem,
            html_host: sxg_input.html_host.clone(),
            sxg_config: serde_yaml::to_string(&sxg_input).unwrap(),
        },
    };
    crate::utils::write_generated_file(
        "cloudflare_worker/wrangler.toml",
        &toml::to_string_pretty(&output).unwrap(),
    )?;
    Ok(())
}
