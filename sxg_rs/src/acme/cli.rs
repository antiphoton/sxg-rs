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

use anyhow::{Error, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
pub struct SxgCredentials {
    pub cert_pem: String,
    pub issuer_pem: String,
}

fn make_temp_dir() -> Result<PathBuf> {
    let output = Command::new("mktemp")
        .args(&["--directory"])
        .output()
        .map_err(|e| Error::new(e).context("Failed to execute mktemp command"))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| Error::new(e).context("The stdout of mktemp contains non-utf8 bytes."))?;
    Ok(PathBuf::from(stdout[..].trim()))
}

const PRIVATE_KEY_FILE: &str = "privkey.pem";
const CERT_REQUEST_FILE: &str = "cert.csr";
const EXTENSION_FILE: &str = "extfile";
const CERT_FILE: &str = "cert.pem";

type Key = (Vec<u8>, (Vec<u8>, Vec<u8>));

fn create_private_key() -> Result<Key> {
    let private_key_der = Command::new("openssl")
        .args(&[
            "ecparam",
            "-outform",
            "der",
            "-name",
            "prime256v1",
            "-genkey",
        ])
        .output()
        .map_err(|e| Error::new(e).context("Failed to use OPENSSL"))?.stdout;
    parse_ec_private_key(&private_key_der)
}

#[deprecated]
fn create_private_key_old<P: AsRef<Path>>(work_dir: P) -> Result<()> {
    Command::new("openssl")
        .current_dir(&work_dir)
        .args(&[
            "ecparam",
            "-out",
            PRIVATE_KEY_FILE,
            "-name",
            "prime256v1",
            "-genkey",
        ])
        .output()
        .map_err(|e| Error::new(e).context("Failed to generate private key"))?;
    Ok(())
}

fn parse_ec_public_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // https://datatracker.ietf.org/doc/html/rfc5480#section-2.2
    //   ECC public keys have the following syntax:
    //     ECPoint ::= OCTET STRING
    //      o The first octet of the OCTET STRING indicates whether the key is
    //        compressed or uncompressed.  The uncompressed form is indicated
    //        by 0x04 and the compressed form is indicated by either 0x02 or
    //        0x03 (see 2.3.3 in [SEC1]).  The public key MUST be rejected if
    //        any other value is included in the first octet.
    let octets = der_parser::parse_ber(&der)?
        .1
        .as_slice()
        .map_err(|e| Error::new(e).context("Expecting ECPoint to be an OCTET STRING"))?;
    const KEY_SIZE: usize = 32; // Both X and Y of the EC Point are 32 bytes (256 bit).
    if octets.len() != 1 + KEY_SIZE * 2 {
        return Err(Error::msg(format!("Expecting ECPoint to contain 1 octet of uncompression flag and {}*2 octets of point coordinates", KEY_SIZE)));
    }
    match octets[0] {
        0x04 => (),
        0x03 => {
            return Err(Error::msg(
                "We don't support ECPoint in compressed form, please use uncompressed form.",
            ))
        }
        _ => return Err(Error::msg("Invalid ECPoint form")),
    };
    let mut x = octets[1..].to_vec();
    let y = x.split_off(KEY_SIZE);
    Ok((x, y))
}

fn parse_ec_private_key(der: &[u8]) -> Result<(Vec<u8>, (Vec<u8>, Vec<u8>))> {
    let ec_private_key = der_parser::parse_ber(der)?.1;
    // https://datatracker.ietf.org/doc/html/rfc5915#section-3
    //   ECPrivateKey ::= SEQUENCE {
    //     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    //     privateKey     OCTET STRING,
    //     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    //     publicKey  [1] BIT STRING OPTIONAL
    //   }
    let private_key = ec_private_key
        .as_sequence()
        .map_err(|e| Error::new(e).context("Expecting ECPrivateKey to be a SEQUENCE"))?
        .get(1)
        .ok_or_else(|| Error::msg("Expecting ECPrivateKey to contain at least 2 items"))?;
    let private_key = private_key
        .as_slice()
        .map_err(|e| Error::new(e).context("Expecting privateKey to be an OCTET STRING"))?
        .to_vec();
    let public_key = parse_ec_public_key(
        ec_private_key
            .as_sequence()?
            .get(3)
            .unwrap()
            .as_slice()
            .unwrap(),
    )?;
    Ok((private_key, public_key))
}

fn parse_private_key_pem<P: AsRef<Path>>(work_dir: P) -> Result<(Vec<u8>, (Vec<u8>, Vec<u8>))> {
    let pem = std::fs::read_to_string(work_dir.as_ref().join(PRIVATE_KEY_FILE))?;
    let der = crate::config::get_der(&pem, "EC PRIVATE KEY")?;
    parse_ec_private_key(&der)
}

fn create_certificate_request<P: AsRef<Path>>(work_dir: P, domain: &str) -> Result<()> {
    Command::new("openssl")
        .current_dir(&work_dir)
        .args(&[
            "req",
            "-new",
            "-sha256",
            "-key",
            PRIVATE_KEY_FILE,
            "-out",
            CERT_REQUEST_FILE,
            "-subj",
            &format!("/CN={}/O=Test/C=US", domain),
        ])
        .output()
        .map_err(|e| Error::new(e).context("Failed to create CSR"))?;
    Ok(())
}

fn sign_certificate<P: AsRef<Path>>(work_dir: P, domain: &str) -> Result<()> {
    std::fs::write(
        work_dir.as_ref().join(EXTENSION_FILE),
        &format!(
            "1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL\nsubjectAltName=DNS:{}",
            domain
        ),
    )?;
    Command::new("openssl")
        .current_dir(&work_dir)
        .args(&[
            "x509",
            "-req",
            "-days",
            "90",
            "-in",
            CERT_REQUEST_FILE,
            "-signkey",
            PRIVATE_KEY_FILE,
            "-out",
            CERT_FILE,
            "-extfile",
            EXTENSION_FILE,
        ])
        .output()
        .map_err(|e| Error::new(e).context("Failed self-sign certificate"))?;
    Ok(())
}

pub fn create_self_signed_certificates() -> Result<SxgCredentials> {
    let work_dir = make_temp_dir().map_err(|e| e.context("Failed to create temp work dir"))?;
    create_private_key_old(&work_dir)?;
    create_certificate_request(&work_dir, "example.com")?;
    sign_certificate(&work_dir, "example.com")?;
    let cert_pem = std::fs::read_to_string(work_dir.join("cert.pem"))?;
    let issuer_pem = cert_pem.clone();
    Ok(SxgCredentials {
        cert_pem,
        issuer_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() -> Result<()> {
        tokio_test::block_on(async {
            let s = include_bytes!("/tmp/tmp.9pE5fVC6Qo/privkey1.der");
            let k = parse_ec_private_key(s).unwrap();
            dbg!(k);
            if 2 > 1 {
                return ;
            }
            create_private_key().unwrap();
            let work_dir: &str = "/tmp/tmp.9pE5fVC6Qo";
            create_private_key_old(work_dir).unwrap();
            create_certificate_request(work_dir, "caoboxiao.com").unwrap();
            let (d, (x, y)) = parse_private_key_pem(work_dir).unwrap();
            let fetcher = crate::fetcher::hyper_fetcher::HyperFetcher::new();
            let signer = crate::signature::rust_signer::RustSigner::new(&d).unwrap();
            let csr_pem =
                std::fs::read_to_string(PathBuf::from(work_dir).join(CERT_REQUEST_FILE)).unwrap();
            let csr_der = crate::config::get_der(&csr_pem, "CERTIFICATE REQUEST").unwrap();
            super::super::get_cert(
                super::super::LETSENCRYPT_STAGING,
                x,
                y,
                &csr_der,
                &fetcher,
                &signer,
            )
            .await
            .unwrap();
        });
        panic!();
    }
}
