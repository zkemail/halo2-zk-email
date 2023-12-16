use clap::{Parser, Subcommand};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
#[cfg(not(target_arch = "wasm32"))]
use halo2_zk_email::helpers::*;
use halo2_zk_email::*;
use std::env::set_var;
use std::fs::File;
use std::path::PathBuf;

#[cfg(not(target_arch = "wasm32"))]
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}
#[cfg(not(target_arch = "wasm32"))]
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
    GenKeys {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        circuit_config_path: String,
        /// emails path
        #[arg(short, long, default_value = "./build/demo.eml")]
        email_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/app.pk")]
        pk_path: String,
        /// verifying key file
        #[arg(long, default_value = "./build/app.vk")]
        vk_path: String,
    },
    Prove {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        circuit_config_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/app.pk")]
        pk_path: String,
        /// emails path
        #[arg(short, long, default_value = "./build/demo.eml")]
        email_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/app.proof")]
        proof_path: String,
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
        #[arg(long, default_value = "./build/app.pk")]
        pk_path: String,
        /// emails path
        #[arg(short, long, default_value = "./build/demo.eml")]
        email_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/app_evm.proof")]
        proof_path: String,
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
        #[arg(long, default_value = "./build/app.vk")]
        vk_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/app.proof")]
        proof_path: String,
        /// public input file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    VerifyWasm {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        circuit_config_path: String,
        /// verifying key file
        #[arg(long, default_value = "./build/app.vk")]
        vk_path: String,
        /// proof hex file
        #[arg(long, default_value = "./build/app_proof.hex")]
        proof_hex_path: String,
        /// public input file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    GenEVMVerifier {
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
        #[arg(long, default_value = "./build/app.vk")]
        vk_path: String,
        /// soldity files directory
        #[arg(short, long, default_value = "./build/sols")]
        sols_dir: String,
        /// the maximum bytes size of each output Solidity code.
        #[arg(short, long)]
        max_line_size_per_file: Option<usize>,
    },
    EVMVerify {
        #[arg(short, long, default_value = "./configs/default_app.config")]
        circuit_config_path: String,
        /// soldity files directory
        #[arg(short, long, default_value = "./build/sols")]
        sols_dir: String,
        /// output proof file
        #[arg(long, default_value = "./build/app_evm.proof")]
        proof_path: String,
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

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenParams { k, params_path } => gen_params(&params_path, k).unwrap(),
        Commands::GenKeys {
            params_path,
            circuit_config_path,
            email_path,
            pk_path,
            vk_path,
        } => {
            let circuit = DefaultEmailVerifyCircuit::<Fr>::gen_circuit_from_email_path(&email_path).await;
            gen_keys(&params_path, &circuit_config_path, &pk_path, &vk_path, circuit).expect("key generation failed");
        }
        Commands::Prove {
            params_path,
            circuit_config_path,
            pk_path,
            email_path,
            proof_path,
            public_input_path,
        } => {
            set_var(EMAIL_VERIFY_CONFIG_ENV, &circuit_config_path);
            let circuit = DefaultEmailVerifyCircuit::<Fr>::gen_circuit_from_email_path(&email_path).await;
            let public_input = circuit.gen_default_public_input();
            prove(&params_path, &circuit_config_path, &pk_path, &proof_path, circuit).unwrap();
            serde_json::to_writer_pretty(File::create(&public_input_path).unwrap(), &public_input).unwrap();
        }
        Commands::EVMProve {
            params_path,
            circuit_config_path,
            pk_path,
            email_path,
            proof_path,
            public_input_path,
        } => {
            set_var(EMAIL_VERIFY_CONFIG_ENV, &circuit_config_path);
            let circuit = DefaultEmailVerifyCircuit::<Fr>::gen_circuit_from_email_path(&email_path).await;
            let public_input = circuit.gen_default_public_input();
            evm_prove(&params_path, &circuit_config_path, &pk_path, &proof_path, circuit).unwrap();
            serde_json::to_writer_pretty(File::create(&public_input_path).unwrap(), &public_input).unwrap();
        }
        Commands::Verify {
            params_path,
            circuit_config_path,
            vk_path,
            proof_path,
            public_input_path,
        } => {
            let result = verify::<DefaultEmailVerifyCircuit<Fr>>(&params_path, &circuit_config_path, &vk_path, &proof_path, &public_input_path).unwrap();
            if result {
                println!("proof is valid");
            } else {
                println!("proof is invalid");
            }
        }
        Commands::VerifyWasm {
            params_path,
            circuit_config_path,
            vk_path,
            proof_hex_path,
            public_input_path,
        } => {
            let result = verify_wasm::<DefaultEmailVerifyCircuit<Fr>>(&params_path, &circuit_config_path, &vk_path, &proof_hex_path, &public_input_path).unwrap();
            if result {
                println!("proof is valid");
            } else {
                println!("proof is invalid");
            }
        }
        Commands::GenEVMVerifier {
            params_path,
            circuit_config_path,
            vk_path,
            sols_dir,
            max_line_size_per_file,
        } => {
            gen_evm_verifier::<DefaultEmailVerifyCircuit<Fr>>(&params_path, &circuit_config_path, &vk_path, &sols_dir, max_line_size_per_file).unwrap();
        }
        Commands::EVMVerify {
            circuit_config_path,
            sols_dir,
            proof_path,
            public_input_path,
        } => {
            evm_verify(&circuit_config_path, &sols_dir, &proof_path, &public_input_path).await.unwrap();
        }
        Commands::GenRegexFiles {
            decomposed_regex_config_path,
            regex_dir_path,
            regex_files_prefix,
        } => gen_regex_files(&decomposed_regex_config_path, &regex_dir_path, &regex_files_prefix).unwrap(),
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {}
