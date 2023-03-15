// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::{config::Config, enums::Mode, pool::ConfigPoolBuilder, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsAcceptor;
use std::{error::Error, fs};
use tokio::{io::AsyncWriteExt, net::TcpListener};
use s2n_tls::{
    callbacks::{VerifyHostNameCallback}
};

/// NOTE: this certificate and key are to be used for demonstration purposes only!
const DEFAULT_TRUST_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/client-cert.pem");
const DEFAULT_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/cert2.pem");
const DEFAULT_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/key2.pem");

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value_t = String::from(DEFAULT_TRUST_CERT))]
    trust: String,
    #[clap(short, long, requires = "key", default_value_t = String::from(DEFAULT_CERT))]
    cert: String,
    #[clap(short, long, requires = "cert", default_value_t = String::from(DEFAULT_KEY))]
    key: String,
    #[clap(short, long, default_value_t = String::from("127.0.0.1:0"))]
    addr: String,
}

pub struct VerifyHostNameClientCertVerifier {
    host_name: String,
}

impl VerifyHostNameCallback for VerifyHostNameClientCertVerifier {
    fn verify_host_name(&self, host_name: &str) -> bool {
        // self.host_name == host_name;
        println!("Connected Host Name {}, Trusted Hostname : {}", host_name, self.host_name);
        if self.host_name == host_name
        {
            return true;
        }
        else {
            return false;
        }
        
    }
}

impl VerifyHostNameClientCertVerifier {
    pub fn new(host_name: impl ToString) -> VerifyHostNameClientCertVerifier {
        VerifyHostNameClientCertVerifier {
            host_name: host_name.to_string(),
        }
    }
}

async fn run_server(trust_pem: &[u8], cert_pem: &[u8], key_pem: &[u8], addr: &str) -> Result<(), Box<dyn Error>> {
    // Set up the configuration for new connections.
    // Minimally you will need a certificate and private key.
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.load_pem(cert_pem, key_pem)?;
    config.trust_pem(trust_pem)?;
    let status = config.set_client_auth_type(s2n_tls::enums::ClientAuthType::Required);
    println!("Client Auth Type : {:?}", status.err());

    config.set_verify_host_callback(VerifyHostNameClientCertVerifier::new("localhost"))?;

    // Create a connection pool to reuse connections.
    let mut pool = ConfigPoolBuilder::new(Mode::Server, config.build()?);
    pool.set_max_pool_size(10);

    // Create the TlsAcceptor based on the pool.
    let server = TlsAcceptor::new(pool.build());

    // Bind to an address and listen for connections.
    // ":0" can be used to automatically assign a port.
    let listener = TcpListener::bind(&addr).await?;
    let addr = listener
        .local_addr()
        .map(|x| x.to_string())
        .unwrap_or_else(|_| "UNKNOWN".to_owned());
    println!("Listening on {}", addr);

    loop {
        // Wait for a client to connect.
        let (stream, peer_addr) = listener.accept().await?;
        println!("Connection from {:?}", peer_addr);

        // Spawn a new task to handle the connection.
        // We probably want to spawn the task BEFORE calling TcpAcceptor::accept,
        // because the TLS handshake can be slow.
        let server = server.clone();
        tokio::spawn(async move {
            let mut tls = server.accept(stream).await?;
            println!("{:#?}", tls);

            // Copy data from the client to stdout
            let mut stdout = tokio::io::stdout();
            tokio::io::copy(&mut tls, &mut stdout).await?;
            tls.shutdown().await?;
            println!("Connection from {:?} closed", peer_addr);

            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let trust_pem = fs::read(args.trust)?;
    let cert_pem = fs::read(args.cert)?;
    let key_pem = fs::read(args.key)?;
    run_server(&trust_pem, &cert_pem, &key_pem, &args.addr).await?;
    Ok(())
}
