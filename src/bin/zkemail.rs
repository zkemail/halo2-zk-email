use clap::{Parser, Subcommand};
use halo2_zk_email::{recursion_and_evm::*, EmailVerifyConfig};
use serde_json::{Result, Value};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand, Clone)]
enum Commands {
    /// Generate a proving key and a verifying key.
    KeyGen {
        #[arg(short, long)]
        /// circuit configure file
        circuit_config: String,
        /// setup parameter file
        #[arg(short, long)]
        params: String,
        /// output proving key file
        #[arg(short, long)]
        pk: String,
        /// output verifying key file
        #[arg(short, long)]
        vk: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::KeyGen {
            circuit_config,
            params,
            pk,
            vk,
        } => {}
    }
}
