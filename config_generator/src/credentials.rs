use std::io::Error as IoError;
use std::process::Command;

use anyhow::{anyhow, Result};
pub struct SxgCredentials {
    pub cert_pem: String,
    pub issuer_pem: String,
}

// Creates self-signed certificates using openssl.
pub fn create_development_certificates(
    work_dir: &std::path::Path,
) -> Result<SxgCredentials, IoError> {
    // DO NOT SUBMIT: use `mktemp`.
    if std::fs::read_dir(&work_dir).is_err() {
        std::fs::create_dir(&work_dir)?;
    }
    Command::new("openssl")
        .current_dir(&work_dir)
        .args(&[
            "ecparam",
            "-out",
            "privkey.pem",
            "-name",
            "prime256v1",
            "-genkey",
        ])
        .output()?;
    Command::new("openssl")
        .current_dir(&work_dir)
        .args(&[
            "req",
            "-new",
            "-sha256",
            "-key",
            "privkey.pem",
            "-out",
            "cert.csr",
            "-subj",
            "/CN=example.org/O=Test/C=US",
        ])
        .output()?;
    std::fs::write(
        work_dir.join("extfile"),
        "1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL\nsubjectAltName=DNS:example.org",
    )?;
    Command::new("openssl")
        .current_dir(&work_dir)
        .args(&[
            "x509",
            "-req",
            "-days",
            "90",
            "-in",
            "cert.csr",
            "-signkey",
            "privkey.pem",
            "-out",
            "cert.pem",
            "-extfile",
            "extfile",
        ])
        .output()?;
    let cert_pem = std::fs::read_to_string(work_dir.join("cert.pem"))?;
    let issuer_pem = cert_pem.clone();
    Ok(SxgCredentials {
        cert_pem,
        issuer_pem,
    })
}

fn read_certificate_pem_file(path: &str) -> Result<String> {
    let text =
        std::fs::read_to_string(path).map_err(|_| format!(r#"Failed to read file "{}""#, path))?;
    // Translate Windows-style line endings to Unix-style so the '\r' is
    // not rendered in the toml. This is purely cosmetic; '\r' is deserialized
    // faithfully from toml and pem::parse_many is able to parse either style.
    let text = text.replace("\r\n", "\n");
    let certs = pem::parse_many(&text)?;
    if certs.len() == 1 && certs[0].tag == "CERTIFICATE" {
        Ok(text)
    } else {
        Err(anyhow!(r#"File "{}" is not a valid certificate PEM"#, path))
    }
}

// Read and parse both `cert.pem` and `issuer.pem`.
// Panics on error.
pub fn read_certificates() -> SxgCredentials {
    let cert = read_certificate_pem_file("credentials/cert.pem");
    let issuer = read_certificate_pem_file("credentials/issuer.pem");
    if cert.is_ok() && issuer.is_ok() {
        println!("Successfully read certificates");
        return SxgCredentials {
            cert_pem: cert.unwrap(),
            issuer_pem: issuer.unwrap(),
        };
    }
    if let Err(msg) = cert {
        println!("{}", msg);
    }
    if let Err(msg) = issuer {
        println!("{}", msg);
    }
    println!(
        r#"Failed to load SXG certificates.
You have two options
  1. Use a development certificate by the command
     {} --create-dev-cert credentials/dev
  2. Use a production certificate according to the link
     https://github.com/google/sxg-rs/blob/main/credentials/README.md"#,
        *super::COMMAND,
    );
    std::process::exit(1);
}
