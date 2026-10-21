//! One-shot REV funder for demos. Signs a `transfer_snippet` under
//! `--from-key` and submits it against a running shard, moving
//! `--amount` REV into `--to-rev`. Useful for setting up a buyer
//! vault before a Story-5 paid-transfer purchase walkthrough.
//!
//! Example:
//!
//! ```shell
//! cargo run -p f1r3drive --example fund -- \
//!     --from-key ~/f1r3drive-demo/alice.hex \
//!     --to-rev 11112…some-base58 \
//!     --amount 1_000_000_000
//! ```

use clap::Parser;
use eyre::{Context, Result};

use f1r3drive_client::{DeployToSign, KeyPair, NodeClient};
use f1r3drive_rho::transfer_snippet;
use f1r3drive_wallet::RevAddress;

#[derive(Parser, Debug)]
struct Args {
    /// Print the base58 REV address derived from `--from-key` and
    /// exit. Useful when you have a hex-encoded signing key and
    /// need the matching vault id.
    #[arg(long)]
    print_rev_only: bool,

    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 40401)]
    port: u16,
    #[arg(long)]
    from_key: std::path::PathBuf,
    #[arg(long, default_value = "")]
    from_rev: String,
    #[arg(long, default_value = "")]
    to_rev: String,
    #[arg(long, default_value_t = 1_000_000_000)]
    amount: i64,
    #[arg(long, default_value = "root")]
    shard_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let signer = KeyPair::from_file(&args.from_key).wrap_err("load from-key")?;
    if args.print_rev_only {
        let rev = RevAddress::from_public_key_bytes(signer.public_key_bytes())
            .wrap_err("derive rev")?
            .to_base58();
        println!("{rev}");
        return Ok(());
    }
    if args.from_rev.is_empty() || args.to_rev.is_empty() {
        eyre::bail!("--from-rev and --to-rev are required when not using --print-rev-only");
    }
    let mut client = NodeClient::connect(&args.host, args.port)
        .await
        .wrap_err("connect")?;

    let term = transfer_snippet(&args.from_rev, &args.to_rev, args.amount);
    let mut to_sign = DeployToSign::new_now(term.term().to_string(), args.shard_id);
    match client.status().await {
        Ok(s) => to_sign.valid_after_block_number = s.last_finalized_block_number.max(0),
        Err(e) if e.is_unimplemented() => {}
        Err(e) => eyre::bail!("status: {e}"),
    }
    let signed = to_sign
        .sign(&signer)
        .map_err(|e| eyre::eyre!("sign: {e}"))?;
    client.do_deploy(signed).await.wrap_err("deploy")?;
    match client.propose(false).await {
        Ok(ack) => println!(
            "funded {} with {} REV: {}",
            args.to_rev, args.amount, ack.message
        ),
        Err(e) if format!("{e}").contains("No new deploys") => {
            println!(
                "funded {} with {} REV (admitted; standalone auto-propose)",
                args.to_rev, args.amount
            );
        }
        Err(e) => eyre::bail!("propose: {e}"),
    }
    Ok(())
}
