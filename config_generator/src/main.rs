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

mod cloudflare;
mod credentials;
mod fastly;
mod utils;

use anyhow::Result;
use once_cell::sync::Lazy;
use serde::Deserialize;
use sxg_rs::config::ConfigInput as SxgInput;

use credentials::SxgCredentials;

#[derive(Deserialize)]
struct Config {
    sxg: SxgInput,
    cloudflare: Option<cloudflare::CloudflareInput>,
    fastly: Option<fastly::FastlyInput>,
}

// Set working directory to the root folder of the "sxg-rs" repository.
fn goto_repository_root() -> Result<()> {
    let exe_path = std::env::current_exe()?;
    assert!(exe_path.ends_with("target/debug/config-generator"));
    let repo_root = exe_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    std::env::set_current_dir(repo_root)?;
    Ok(())
}

static COMMAND: Lazy<String> = Lazy::new(|| {
    let args: Vec<_> = std::env::args().skip(1).collect();
    format!("cargo run -p config-generator -- {}", args.join(" "))
});

const INPUT_FILE: &'static str = "config_generator/config.yaml";
const INPUT_EXAMPLE_FILE: &'static str = "config_generator/config.example.yaml";

// Read and parse `config.yaml`.
// If `config.yaml` does not exist, it will be copied from `config.example.yaml`.
// This function panics if `config.yaml` contains syntax error,
// even when a valid `config.example.yaml` exists.
fn read_existing_config() -> Result<Config> {
    let (config, exists) = std::fs::read_to_string(INPUT_FILE)
        .map(|s| (s, true))
        .or_else(|_| std::fs::read_to_string(INPUT_EXAMPLE_FILE).map(|s| (s, false)))?;
    if exists == false {
        std::fs::write(INPUT_FILE, config.clone())?
    }
    Ok(serde_yaml::from_str(&config).unwrap())
}

fn main() -> Result<()> {
    goto_repository_root()?;
    let yaml = clap::load_yaml!("cli.yaml");
    let args = clap::App::from_yaml(yaml).get_matches();
    let credentials = match args.value_of("create_dev_cert") {
        Some(work_dir) => {
            let work_dir = std::path::Path::new(work_dir);
            credentials::create_development_certificates(&work_dir)?
        }
        None => credentials::read_certificates(),
    };
    let config = read_existing_config()?;
    match args.value_of("target") {
        Some("cloudflare") => {
            let input = config.cloudflare.expect(&format!(
                r#""cloudflare" section is not found in the "{}" file"#,
                INPUT_FILE
            ));
            cloudflare::run(credentials, config.sxg, input)?
        }
        Some("fastly") => {
            let input = config.fastly.expect(&format!(
                r#""fastly" section is not found in the "{}" file"#,
                INPUT_FILE
            ));
            fastly::run(config.sxg, input)?
        }
        _ => unreachable!(""),
    };
    Ok(())
}
