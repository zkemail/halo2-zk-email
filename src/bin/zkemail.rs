use clap::{Parser, Subcommand};
use halo2_zk_email::helpers::gen_pks_and_vks;
use halo2_zk_email::helpers::*;
use halo2_zk_email::*;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand, Clone)]
enum Commands {
    /// Generate a setup parameter (not for production).
    GenParams {
        /// k parameter for the one email verification circuit.
        #[arg(long)]
        k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
    },
    /// Generate proving keys and verifying keys.
    GenPksAndVks {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        circuit_config_path: String,
        /// emails path
        #[arg(short, long, default_value = "./build/demo.eml")]
        email_path: String,
        #[arg(short, long, default_value = "0")]
        tag: Option<String>,
        /// proving key path
        #[arg(long, default_value = "./build/pks")]
        pks_dir: String,
        /// verifying key file
        #[arg(long, default_value = "./build/vks")]
        vks_dir: String,
    },
    Prove {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        circuit_config_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/pks")]
        pks_dir: String,
        /// emails path
        #[arg(short, long, default_value = "./build/demo.eml")]
        email_path: String,
        #[arg(short, long, default_value = "0")]
        tag: Option<String>,
        /// output proof file
        #[arg(long, default_value = "./build/proofs")]
        proofs_dir: String,
        /// public input file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    EVMProve {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        circuit_config_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/pks")]
        pks_dir: String,
        /// emails path
        #[arg(short, long, default_value = "./build/demo.eml")]
        email_path: String,
        #[arg(short, long, default_value = "0")]
        tag: Option<String>,
        /// output proof file
        #[arg(long, default_value = "./build/evm_proofs")]
        proofs_dir: String,
        /// public input file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    Verify {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        circuit_config_path: String,
        /// verifying key file
        #[arg(long, default_value = "./build/vks")]
        vks_dir: String,
        /// output proof file
        #[arg(long, default_value = "./build/proofs")]
        proofs_dir: String,
        /// public input file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    GenEVMVerifiers {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        circuit_config_path: String,
        // /// emails path
        // #[arg(short, long, default_value = "./build/demo.eml")]
        // email_path: String,
        /// verifying key file
        #[arg(long, default_value = "./build/vks")]
        vks_dir: String,
        /// soldity files directory
        #[arg(short, long, default_value = "./build/sols")]
        sols_dir: String,
    },
    EVMVerify {
        #[arg(short, long, default_value = "./configs/default_app.config")]
        circuit_config_path: String,
        /// soldity files directory
        #[arg(short, long, default_value = "./build/sols")]
        sols_dir: String,
        /// output proof file
        #[arg(long, default_value = "./build/evm_proofs")]
        proofs_dir: String,
        /// public input file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    GenRegexFiles {
        #[arg(short, long, default_value = "./configs/decomposed_regex_config.json")]
        decomposed_regex_config_path: String,
        #[arg(long, default_value = "./build")]
        regex_dir_path: String,
        #[arg(short, long)]
        regex_files_prefix: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenParams { k, params_path } => gen_params(&PathBuf::new().join(params_path), k).unwrap(),
        Commands::GenPksAndVks {
            params_path,
            circuit_config_path,
            email_path,
            tag,
            pks_dir,
            vks_dir,
        } => {
            gen_pks_and_vks(
                &PathBuf::new().join(params_path),
                &PathBuf::new().join(circuit_config_path),
                &PathBuf::new().join(email_path),
                tag,
                &PathBuf::new().join(pks_dir),
                &PathBuf::new().join(vks_dir),
            )
            .await
            .expect("key generation failed");
        }
        Commands::Prove {
            params_path,
            circuit_config_path,
            pks_dir,
            email_path,
            tag,
            proofs_dir,
            public_input_path,
        } => {
            prove(
                &PathBuf::new().join(params_path),
                &PathBuf::new().join(circuit_config_path),
                &PathBuf::new().join(pks_dir),
                tag,
                &PathBuf::new().join(email_path),
                &PathBuf::new().join(proofs_dir),
                &PathBuf::new().join(public_input_path),
            )
            .await
            .expect("proof generation failed");
        }
        Commands::EVMProve {
            params_path,
            circuit_config_path,
            pks_dir,
            email_path,
            tag,
            proofs_dir,
            public_input_path,
        } => {
            evm_prove(
                &PathBuf::new().join(params_path),
                &PathBuf::new().join(circuit_config_path),
                &PathBuf::new().join(pks_dir),
                tag,
                &PathBuf::new().join(email_path),
                &PathBuf::new().join(proofs_dir),
                &PathBuf::new().join(public_input_path),
            )
            .await
            .expect("evm proof generation failed");
        }
        Commands::Verify {
            params_path,
            circuit_config_path,
            vks_dir,
            proofs_dir,
            public_input_path,
        } => {
            let result = verify(
                &PathBuf::new().join(params_path),
                &PathBuf::new().join(circuit_config_path),
                &PathBuf::new().join(vks_dir),
                &PathBuf::new().join(proofs_dir),
                &PathBuf::new().join(public_input_path),
            );
            assert!(result);
        }
        Commands::GenEVMVerifiers {
            params_path,
            circuit_config_path,
            vks_dir,
            sols_dir,
        } => {
            gen_evm_verifiers(
                &PathBuf::new().join(params_path),
                &PathBuf::new().join(circuit_config_path),
                &PathBuf::new().join(vks_dir),
                &PathBuf::new().join(sols_dir),
            );
        }
        Commands::EVMVerify {
            circuit_config_path,
            sols_dir,
            proofs_dir,
            public_input_path,
        } => {
            evm_verify(
                &PathBuf::new().join(circuit_config_path),
                &PathBuf::new().join(sols_dir),
                &PathBuf::new().join(proofs_dir),
                &PathBuf::new().join(public_input_path),
            )
            .await;
        }
        Commands::GenRegexFiles {
            decomposed_regex_config_path,
            regex_dir_path,
            regex_files_prefix,
        } => gen_regex_files(&decomposed_regex_config_path, &regex_dir_path, &regex_files_prefix).unwrap(),
    }
}
