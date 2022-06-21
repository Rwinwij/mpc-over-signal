use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use std::path::PathBuf;
use structopt::StructOpt;

use gg20_mpc::*;
use round_based::async_runtime::AsyncProtocol;

#[tokio::main]
async fn main() -> Result<()> {

    let (keyshare, pubkey_x, pubkey_y, pubkey_point) = gg20_mpc::keygen_run(2,2).await.unwrap();
    println!("\n\nkeyshare = {:?}",keyshare);
    println!("\n\npubkey_x = {:?}",pubkey_x);
    println!("\n\npubkey_y = {:?}",pubkey_y);
    println!("\n\npubkey_point = {:?}",pubkey_point);
    //println!("{:?}",result);
    Ok(())

}