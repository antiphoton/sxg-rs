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

use super::{read_certificate_pem_file, Artifact, SxgCertConfig};
use crate::linux_commands::execute_and_parse_stdout;
use anyhow::{anyhow, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::process::Command;
use sxg_rs::config::Config as SxgConfig;

#[derive(Debug, Deserialize, Serialize)]
pub struct FastlySpecificInput {
    pub service_name_prefix: String,
}

// https://developer.fastly.com/reference/compute/fastly-toml/
#[derive(Serialize)]
struct FastlyManifest {
    name: String,
    authors: Vec<String>,
    service_id: String,
    language: &'static str,
    manifest_version: u8,
    // dictionaries: BTreeMap<&'static str, EdgeDictionary>,
}

#[derive(Serialize)]
struct EdgeDictionary {
    items: Vec<EdgeDictionaryItem>,
}

#[derive(Serialize)]
struct EdgeDictionaryItem {
    key: &'static str,
    value: String,
}

const OUTPUT_FILE: &str = "fastly_compute/fastly.toml";

fn random_service_name(prefix: &str) -> String {
    let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
    format!("{}_{}", prefix, now)
}

fn capture_regex_groups<'a, 'b>(text: &'a str, re: &'b str) -> Result<Vec<Option<&'a str>>> {
    let re = Regex::new(re)?;
    let captures = re
        .captures(text)
        .ok_or_else(|| anyhow!(r#"Text "{}" does not match regex "{}""#, text, re))?;
    let groups: Vec<_> = captures
        .iter()
        .into_iter()
        .map(|x| Some(x?.as_str()))
        .collect();
    Ok(groups)
}

fn create_service(name: &str) -> Result<String> {
    let stdout = execute_and_parse_stdout(
        Command::new("fastly")
            .arg("service")
            .arg("create")
            .arg("--type")
            .arg("wasm")
            .arg("--name")
            .arg(name),
    )?;
    let captures = capture_regex_groups(&stdout, r"Created service (\w+)\n")?;
    let service_id = captures[1].unwrap().to_string();
    // DO NOT SUBMIT
    println!("Created Fastly service {}", service_id);
    Ok(service_id)
}

fn create_dictionary(service_id: &str, dictionary_name: &str, write_only: bool) -> Result<()> {
    let s = execute_and_parse_stdout(
        Command::new("fastly")
            .arg("dictionary")
            .arg("create")
            .arg("--service-id")
            .arg(service_id)
            .arg("--version")
            .arg("latest")
            .arg("--name")
            .arg(dictionary_name)
            .arg("--write-only")
            .arg(format!("{}", write_only)),
    )?;
    dbg!(s);
    Ok(())
}

fn find_dictionary_id(service_id: &str, dictionary_name: &str) -> Result<String> {
    let stdout = execute_and_parse_stdout(
        Command::new("fastly")
            .arg("dictionary")
            .arg("list")
            .arg("--service-id")
            .arg(service_id)
            .arg("--version")
            .arg("latest"),
    )?;
    let captures =
        capture_regex_groups(&stdout, &format!(r"ID: (\w+)\nName: {}", dictionary_name))?;
    Ok(captures[1].unwrap().to_string())
}

pub fn create_dictionary_item(
    service_id: &str,
    dictionary_id: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    execute_and_parse_stdout(
        Command::new("fastly")
            .arg("dictionary-item")
            .arg("create")
            .arg("--service-id")
            .arg(service_id)
            .arg("--dictionary-id")
            .arg(dictionary_id)
            .arg("--key")
            .arg(key)
            .arg("--value")
            .arg(value),
    )?;
    Ok(())
}

pub fn update_dictionary_item(
    service_id: &str,
    dictionary_id: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    execute_and_parse_stdout(
        Command::new("fastly")
            .arg("dictionary-item")
            .arg("update")
            .arg("--service-id")
            .arg(service_id)
            .arg("--dictionary-id")
            .arg(dictionary_id)
            .arg("--key")
            .arg(key)
            .arg("--value")
            .arg(value),
    )?;
    Ok(())
}

pub fn main(
    _use_ci_mode: bool,
    sxg_input: &SxgConfig,
    cert_input: &SxgCertConfig,
    fastly_input: &FastlySpecificInput,
    artifact: &mut Artifact,
) -> Result<()> {
    let mut sxg_input = sxg_input.clone();
    // DO NOT SUBMIT
    sxg_input.private_key_base64 = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string());
    let service_name = random_service_name(&fastly_input.service_name_prefix);
    let service_id = create_service(&service_name)?;
    artifact.fastly_service_id = Some(service_id.clone()); // DO_NOT SUBMIT
    create_dictionary(&service_id, "config", false)?;
    let dictionary_id = find_dictionary_id(&service_id, "config")?;
    artifact.fastly_dictionary_id = Some(dictionary_id.clone()); // DO_NOT SUBMIT
    create_dictionary_item(
        &service_id,
        &dictionary_id,
        "sxg-config-input",
        &serde_json::to_string(&sxg_input)?,
    )?;
    match &cert_input {
        SxgCertConfig::PreIssued {
            cert_file,
            issuer_file,
        } => {
            create_dictionary_item(
                &service_id,
                &dictionary_id,
                "cert-pem",
                &read_certificate_pem_file(cert_file)?,
            )?;
            create_dictionary_item(
                &service_id,
                &dictionary_id,
                "issuer-pem",
                &read_certificate_pem_file(issuer_file)?,
            )?;
        }
        SxgCertConfig::CreateAcmeAccount(_) => {}
    };
    let fastly_manifest = FastlyManifest {
        name: service_name,
        service_id,
        authors: vec![],
        language: "rust",
        manifest_version: 1,
        // dictionaries: vec![(
        //     "config",
        //     EdgeDictionary {
        //         items: dictionary_items,
        //     },
        // )]
        // .into_iter()
        // .collect(),
    };

    std::fs::write(
        OUTPUT_FILE,
        format!(
            "# This file is generated by command \"cargo run -p tools -- gen-config\".\n\
            # Please note that anything you modify won't be preserved\n\
            # at the next time you run \"cargo run -p tools -- -gen-config\".\n\
            {}",
            toml::to_string_pretty(&fastly_manifest)?
        ),
    )?;
    println!("Successfully wrote config to {}", OUTPUT_FILE);
    Ok(())
}
