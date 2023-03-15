// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::{config::Config, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsConnector;
use std::{error::Error, fs};
use tokio::{io::AsyncWriteExt, net::TcpStream};

/// NOTE: this certificate is to be used for demonstration purposes only!
const DEFAULT_TRUST_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/cert2.pem");
const DEFAULT_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/client-cert.pem");
const DEFAULT_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/client-key.pem");

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value_t = String::from(DEFAULT_TRUST_CERT))]
    trust: String,
    #[clap(short, long, requires = "key", default_value_t = String::from(DEFAULT_CERT))]
    cert: String,
    #[clap(short, long, requires = "cert", default_value_t = String::from(DEFAULT_KEY))]
    key: String,
    addr: String,
}

async fn run_client(trust_pem: &[u8], cert_pem: &[u8], key_pem: &[u8], addr: &str) -> Result<(), Box<dyn Error>> {
    // Set up the configuration for new connections.
    // Minimally you will need a trust store.
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.load_pem(cert_pem, key_pem)?;
    config.trust_pem(trust_pem)?;
    let status = config.set_client_auth_type(s2n_tls::enums::ClientAuthType::Required);
    println!("Client Auth Type Error ? {:?}", status.err());

    // Create the TlsConnector based on the configuration.
    let client = TlsConnector::new(config.build()?);

    // Connect to the server.
    let stream = TcpStream::connect(addr).await?;
    let tls = client.connect("localhost", stream).await?;
    println!("{:#?}", tls);

    // Split the stream.
    // This allows us to call read and write from different tasks.
    let (mut reader, mut writer) = tokio::io::split(tls);

    // Copy data from the server to stdout
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        tokio::io::copy(&mut reader, &mut stdout).await
    });

    // Send data from stdin to the server
    let mut stdin = tokio::io::stdin();
    tokio::io::copy(&mut stdin, &mut writer).await?;
    writer.shutdown().await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let trust_pem = fs::read(args.trust)?;
    let cert_pem = fs::read(args.cert)?;
    let key_pem = fs::read(args.key)?;
    run_client(&trust_pem, &cert_pem, &key_pem, &args.addr).await?;
    Ok(())
}
