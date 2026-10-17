//! Walkthrough CLI for `demo/vendor_contract.rho`.
//!
//! Four subcommands matching the four demo steps:
//!
//! | subcommand         | role     | what it does                                                |
//! |--------------------|----------|-------------------------------------------------------------|
//! | `deploy-vendor`    | Alice    | signs + submits the Rholang vendor contract                |
//! | `transfer`         | payer    | sends REV to a REV address via `rho:vault:system`          |
//! | `fetch`            | payer    | exploratory-deploys a call to Alice's vendor channel       |
//! | `buy`              | payer    | `transfer` then `fetch`, writes the content to a local file |
//!
//! The vendor contract trusts the caller to have paid; see
//! `demo/vendor_contract.rho` for the trust model.

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use eyre::{bail, Context};

use f1r3drive_client::{DeployToSign, KeyPair, NodeClient};
use f1r3drive_proto::rhoapi::expr::ExprInstance;
use f1r3drive_proto::rhoapi::Par;
use f1r3drive_rho::transfer_snippet;

/// Well-known channel where Alice publishes her vendor contract.
/// Matches the string literal in `demo/vendor_contract.rho`.
const VENDOR_CHANNEL: &str = "demo:alice:vendor:v1";

#[derive(Debug, Parser)]
#[command(
    name = "demo-vendor",
    about = "Pay-for-content vendor contract walkthrough"
)]
struct Cli {
    /// Node gRPC endpoint.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 40401)]
    port: u16,
    /// Shard ID baked into every signed deploy.
    #[arg(long, default_value = "root")]
    shard_id: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Print the REV address derived from a secp256k1 key file.
    /// Doesn't touch the node; useful for demo setup scripts.
    DeriveAddress {
        #[arg(long)]
        key_file: PathBuf,
    },

    /// Alice: deploy the vendor contract from a Rholang source file.
    DeployVendor {
        #[arg(long)]
        key_file: PathBuf,
        /// Path to `vendor_contract.rho` (or any Rholang file).
        #[arg(long)]
        rho_file: PathBuf,
    },

    /// Payer: raw REV transfer. Same operation `WalletFs::rename`
    /// performs when the user drags a `*.token` across wallet dirs.
    Transfer {
        #[arg(long)]
        key_file: PathBuf,
        /// Base58 REV address to send to.
        #[arg(long)]
        to: String,
        /// REV to send (payer must have >= amount + phlo cost).
        #[arg(long)]
        amount: i64,
    },

    /// Payer: call Alice's vendor via exploratory-deploy to retrieve
    /// a file. Doesn't modify on-chain state; prints the file content
    /// to stdout.
    Fetch {
        /// Name of the file in the vendor's library.
        #[arg(long)]
        file: String,
        /// Payment amount to claim in the request (must match or
        /// exceed the vendor's price).
        #[arg(long, default_value_t = 100)]
        amount: i64,
    },

    /// Payer: combined flow — transfer + fetch + save-to-local-file.
    /// This is what a Finder drag SHOULD do once the mount grows a
    /// contract-folder shape; until then, we invoke it manually.
    Buy {
        #[arg(long)]
        key_file: PathBuf,
        /// Alice's REV address (destination of the transfer).
        #[arg(long)]
        alice_address: String,
        /// File name to request.
        #[arg(long)]
        file: String,
        /// Price in REV. Must equal or exceed the vendor's threshold.
        #[arg(long, default_value_t = 100)]
        price: i64,
        /// Where to write the retrieved content. Defaults to
        /// `~/Downloads/<file>` so it's immediately drag-able to the
        /// desktop.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("demo_vendor=info")),
        )
        .init();

    let cli = Cli::parse();

    // DeriveAddress is pure — don't open a gRPC connection for it.
    if let Cmd::DeriveAddress { key_file } = &cli.cmd {
        let signer = KeyPair::from_file(key_file)
            .wrap_err_with(|| format!("load key {}", key_file.display()))?;
        println!("{}", derive_rev_address(&signer)?);
        return Ok(());
    }

    let mut client = NodeClient::connect(&cli.host, cli.port)
        .await
        .wrap_err_with(|| format!("connect to {}:{}", cli.host, cli.port))?;

    match cli.cmd {
        Cmd::DeriveAddress { .. } => unreachable!("handled above"),
        Cmd::DeployVendor { key_file, rho_file } => {
            let signer = KeyPair::from_file(&key_file)
                .wrap_err_with(|| format!("load key {}", key_file.display()))?;
            let term = fs::read_to_string(&rho_file)
                .wrap_err_with(|| format!("read {}", rho_file.display()))?;
            submit_mutating(&mut client, &signer, &cli.shard_id, term, "deploy-vendor").await?;
            println!("vendor deployed. channel: @\"{VENDOR_CHANNEL}\"");
        }

        Cmd::Transfer {
            key_file,
            to,
            amount,
        } => {
            let signer = KeyPair::from_file(&key_file)
                .wrap_err_with(|| format!("load key {}", key_file.display()))?;
            let from = derive_rev_address(&signer)?;
            let term = transfer_snippet(&from, &to, amount).term().to_string();
            submit_mutating(&mut client, &signer, &cli.shard_id, term, "transfer").await?;
            println!("transfer submitted: {amount} REV {from} → {to}");
        }

        Cmd::Fetch { file, amount } => {
            let content = call_vendor(&mut client, &file, amount).await?;
            print!("{content}");
        }

        Cmd::Buy {
            key_file,
            alice_address,
            file,
            price,
            output,
        } => {
            let signer = KeyPair::from_file(&key_file)
                .wrap_err_with(|| format!("load key {}", key_file.display()))?;
            let payer = derive_rev_address(&signer)?;

            // (1) Pay Alice. In the UI world this is the drag of a
            // `*.token` from the payer's `.tokens/` into Alice's
            // wallet directory.
            let xfer = transfer_snippet(&payer, &alice_address, price)
                .term()
                .to_string();
            submit_mutating(&mut client, &signer, &cli.shard_id, xfer, "buy/transfer").await?;
            eprintln!("[1/3] transfer: {price} REV {payer} → {alice_address}");

            // (2) Fetch the content. Exploratory deploy — no block,
            // no cost beyond gRPC round-trip.
            let content = call_vendor(&mut client, &file, price).await?;
            eprintln!("[2/3] fetched: {} bytes", content.len());

            // (3) Save locally. Default to ~/Downloads/<file>.
            let out = output.unwrap_or_else(|| {
                dirs_home()
                    .map(|h| h.join("Downloads").join(&file))
                    .unwrap_or_else(|| PathBuf::from(&file))
            });
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent).ok();
            }
            fs::write(&out, &content).wrap_err_with(|| format!("write {}", out.display()))?;
            eprintln!("[3/3] saved to: {}", out.display());
        }
    }
    Ok(())
}

/// Sign + submit a mutating Rholang deploy, then propose. Mirrors
/// the production `F1r3Fs::run_mutating_snippet` pattern.
async fn submit_mutating(
    client: &mut NodeClient,
    signer: &KeyPair,
    shard_id: &str,
    term: String,
    label: &str,
) -> eyre::Result<()> {
    let mut to_sign = DeployToSign::new_now(term, shard_id.to_string());
    match client.status().await {
        Ok(s) => to_sign.valid_after_block_number = s.last_finalized_block_number.max(0),
        Err(e) if e.is_unimplemented() => {
            tracing::debug!("node has no status RPC; using valid_after_block_number=0");
        }
        Err(e) => return Err(eyre::eyre!("{label}: status: {e}")),
    }
    let signed = to_sign
        .sign(signer)
        .map_err(|e| eyre::eyre!("{label}: sign: {e}"))?;
    client
        .do_deploy(signed)
        .await
        .map_err(|e| eyre::eyre!("{label}: do_deploy: {e}"))?;
    client
        .propose(false)
        .await
        .map_err(|e| eyre::eyre!("{label}: propose: {e}"))?;
    Ok(())
}

/// Build the Rholang that peeks Alice's vendor channel and calls it;
/// run via `exploratory_deploy`; return the content string.
async fn call_vendor(client: &mut NodeClient, file: &str, amount: i64) -> eyre::Result<String> {
    // Escape embedded quotes in the filename for safety against
    // misshapen inputs (filenames come from CLI).
    let safe_file = file.replace('\\', "\\\\").replace('"', "\\\"");
    let term = format!(
        "new return, ackCh in {{\n  \
         for (vendor <<- @\"{channel}\") {{\n    \
         @*vendor!({amount}, \"{file}\", *ackCh) |\n    \
         for (@reply <- ackCh) {{\n      \
         return!(reply)\n    \
         }}\n  \
         }}\n\
         }}",
        channel = VENDOR_CHANNEL,
        amount = amount,
        file = safe_file,
    );
    let result = client
        .exploratory_deploy(&term, "", false)
        .await
        .map_err(|e| eyre::eyre!("vendor call: {e}"))?;
    decode_vendor_reply(&result.pars)
}

/// Decode `(true, content) | (false, reason)` from the vendor's ack.
/// Rholang tuples surface as `ETupleBody`; strings as `GString`.
fn decode_vendor_reply(pars: &[Par]) -> eyre::Result<String> {
    if pars.is_empty() {
        bail!("vendor returned no reply — check that the vendor contract was deployed and the channel URN matches");
    }
    let par = &pars[0];
    let first = par.exprs.first().ok_or_else(|| eyre::eyre!("empty Par"))?;
    let elems = match &first.expr_instance {
        Some(ExprInstance::ETupleBody(t)) => &t.ps,
        Some(ExprInstance::EListBody(l)) => &l.ps,
        _ => bail!("vendor reply is not a tuple/list"),
    };
    if elems.len() != 2 {
        bail!("vendor reply is a {}-tuple; expected 2", elems.len());
    }
    let ok = match elems[0]
        .exprs
        .first()
        .and_then(|e| e.expr_instance.as_ref())
    {
        Some(ExprInstance::GBool(b)) => *b,
        _ => bail!("first element of vendor reply is not a bool"),
    };
    let msg = match elems[1]
        .exprs
        .first()
        .and_then(|e| e.expr_instance.as_ref())
    {
        Some(ExprInstance::GString(s)) => s.clone(),
        _ => bail!("second element of vendor reply is not a string"),
    };
    if ok {
        Ok(msg)
    } else {
        bail!("vendor refused: {msg}");
    }
}

/// Derive the payer's REV address from their signing key. Same path
/// `WalletFs` uses when the user unlocks via `--unlock-key-file`.
fn derive_rev_address(signer: &KeyPair) -> eyre::Result<String> {
    f1r3drive_wallet::RevAddress::from_public_key_bytes(signer.public_key_bytes())
        .map(|a| a.to_base58())
        .map_err(|e| eyre::eyre!("derive REV address: {e}"))
}

/// Minimal `$HOME` fetch — avoids pulling the `dirs` crate for one call.
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
