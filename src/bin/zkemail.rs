use cfdkim::{canonicalize_signed_email, resolve_public_key};
use clap::{Parser, Subcommand};
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use halo2_zk_email::utils::{get_email_circuit_public_hash_input, get_email_substrs, read_default_circuit_config_params};
use halo2_zk_email::*;
use hex;
use itertools::Itertools;
use num_bigint::BigUint;
use rsa::PublicKeyParts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier::loader::LoadedScalar;
use std::env::set_var;
use std::fs::{self, File};
use std::io::{Read, Write};

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
        #[arg(short, long, default_value = "./build/agg_params.bin")]
        params_path: String,
    },
    /// Downsize a setup parameter (not for production).
    DownsizeParams {
        /// k parameter for the one email verification circuit.
        #[arg(long)]
        k: u32,
        /// original setup parameters path
        #[arg(short, long, default_value = "./build/agg_params.bin")]
        original_params_path: String,
        /// downsized setup parameters path
        #[arg(short, long, default_value = "./build/app_params.bin")]
        new_params_path: String,
    },
    /// Generate a proving key and a verifying key.
    GenAppKey {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/app_params.bin")]
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
    /// Generate a proving key and a verifying key.
    GenAggKey {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/app_params.bin")]
        app_params_path: String,
        /// setup parameters path
        #[arg(short, long, default_value = "./build/agg_params.bin")]
        agg_params_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        app_circuit_config_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_agg.config")]
        agg_circuit_config_path: String,
        /// emails path
        #[arg(short, long, default_value = "./build/demo.eml")]
        email_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/app.pk")]
        app_pk_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/agg.pk")]
        agg_pk_path: String,
        /// verifying key file
        #[arg(long, default_value = "./build/agg.vk")]
        agg_vk_path: String,
    },
    ProveApp {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/app_params.bin")]
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
        #[arg(long, default_value = "./build/app_proof.bin")]
        proof_path: String,
        /// public input file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    EVMProveApp {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/app_params.bin")]
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
        #[arg(long, default_value = "./build/evm_app_proof.hex")]
        proof_path: String,
        /// public input file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    EVMProveAgg {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/app_params.bin")]
        app_params_path: String,
        /// setup parameters path
        #[arg(short, long, default_value = "./build/agg_params.bin")]
        agg_params_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        app_circuit_config_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_agg.config")]
        agg_circuit_config_path: String,
        /// emails path
        #[arg(short, long, default_value = "./build/demo.eml")]
        email_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/app.pk")]
        app_pk_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/agg.pk")]
        agg_pk_path: String,
        /// output acc file
        #[arg(long, default_value = "./build/evm_agg_acc.hex")]
        acc_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/evm_agg_proof.hex")]
        proof_path: String,
        /// public input file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    GenEVMVerifier {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/app_params.bin")]
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
        /// evm verifier file
        #[arg(short, long, default_value = "./build/verifier.bin")]
        bytecode_path: String,
        /// evm verifier file
        #[arg(short, long, default_value = "./build/Verifier.sol")]
        solidity_path: String,
    },
    GenAggEVMVerifier {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/agg_params.bin")]
        agg_params_path: String,
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        app_circuit_config_path: String,
        /// aggregation circuit configure file
        #[arg(short, long, default_value = "./configs/default_agg.config")]
        agg_circuit_config_path: String,
        // /// emails path
        // #[arg(short, long, default_value = "./build/demo.eml")]
        // email_path: String,
        /// verifying key file
        #[arg(long, default_value = "./build/agg.vk")]
        vk_path: String,
        /// evm verifier file
        #[arg(short, long, default_value = "./build/verifier.bin")]
        bytecode_path: String,
        /// evm verifier file
        #[arg(short, long, default_value = "./build/Verifier.sol")]
        solidity_path: String,
    },
    EVMVerifyApp {
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        circuit_config_path: String,
        /// evm verifier file
        #[arg(short, long, default_value = "./build/verifier.bin")]
        bytecode_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/evm_app_proof.hex")]
        proof_path: String,
        /// public input file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    EVMVerifyAgg {
        /// email verification circuit configure file
        #[arg(short, long, default_value = "./configs/default_app.config")]
        app_circuit_config_path: String,
        /// aggregation circuit configure file
        #[arg(short, long, default_value = "./configs/default_agg.config")]
        agg_circuit_config_path: String,
        /// evm verifier file
        #[arg(short, long, default_value = "./build/verifier.bin")]
        bytecode_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/evm_agg_proof.hex")]
        proof_path: String,
        /// output acc file
        #[arg(long, default_value = "./build/evm_agg_acc.hex")]
        acc_path: String,
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
        Commands::GenParams { k, params_path } => gen_params(&params_path, k).unwrap(),
        Commands::DownsizeParams {
            k,
            original_params_path,
            new_params_path,
        } => downsize_params(&original_params_path, &new_params_path, k).unwrap(),
        Commands::GenAppKey {
            params_path,
            circuit_config_path,
            email_path,
            pk_path,
            vk_path,
        } => {
            set_var(EMAIL_VERIFY_CONFIG_ENV, &circuit_config_path);
            let (circuit, _, _, _, _) = gen_circuit_from_email_path(&email_path).await;
            gen_app_key::<DefaultEmailVerifyCircuit<Fr>>(&params_path, &circuit_config_path, &pk_path, &vk_path, circuit)
                .await
                .unwrap()
        }
        Commands::GenAggKey {
            app_params_path,
            agg_params_path,
            app_circuit_config_path,
            agg_circuit_config_path,
            email_path,
            app_pk_path,
            agg_pk_path,
            agg_vk_path,
        } => {
            set_var(EMAIL_VERIFY_CONFIG_ENV, &app_circuit_config_path);
            set_var(VERIFY_CONFIG_KEY, &agg_circuit_config_path);
            let (circuit, _, _, _, _) = gen_circuit_from_email_path(&email_path).await;
            gen_agg_key::<DefaultEmailVerifyCircuit<Fr>>(
                &app_params_path,
                &agg_params_path,
                &app_circuit_config_path,
                &agg_circuit_config_path,
                &app_pk_path,
                &agg_pk_path,
                &agg_vk_path,
                circuit,
            )
            .await
            .unwrap()
        }
        Commands::ProveApp {
            params_path,
            circuit_config_path,
            pk_path,
            email_path,
            proof_path,
            public_input_path,
        } => {
            set_var(EMAIL_VERIFY_CONFIG_ENV, &circuit_config_path);
            let (circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(&email_path).await;
            prove_app::<DefaultEmailVerifyCircuit<Fr>>(&params_path, &circuit_config_path, &pk_path, &proof_path, circuit)
                .await
                .unwrap();
            gen_default_public_input(headerhash, public_key_n, header_substrs, body_substrs, &public_input_path).await;
        }
        Commands::EVMProveApp {
            params_path,
            circuit_config_path,
            pk_path,
            email_path,
            proof_path,
            public_input_path,
        } => {
            set_var(EMAIL_VERIFY_CONFIG_ENV, &circuit_config_path);
            let (circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(&email_path).await;
            evm_prove_app::<DefaultEmailVerifyCircuit<Fr>>(&params_path, &circuit_config_path, &pk_path, &proof_path, circuit)
                .await
                .unwrap();
            gen_default_public_input(headerhash, public_key_n, header_substrs, body_substrs, &public_input_path).await;
        }
        Commands::EVMProveAgg {
            app_params_path,
            agg_params_path,
            app_circuit_config_path,
            agg_circuit_config_path,
            email_path,
            app_pk_path,
            agg_pk_path,
            acc_path,
            proof_path,
            public_input_path,
        } => {
            set_var(EMAIL_VERIFY_CONFIG_ENV, &app_circuit_config_path);
            set_var(VERIFY_CONFIG_KEY, &agg_circuit_config_path);
            let (circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(&email_path).await;
            evm_prove_agg::<DefaultEmailVerifyCircuit<Fr>>(
                &app_params_path,
                &agg_params_path,
                &app_circuit_config_path,
                &agg_circuit_config_path,
                &app_pk_path,
                &agg_pk_path,
                &acc_path,
                &proof_path,
                circuit,
            )
            .await
            .unwrap();
            gen_default_public_input(headerhash, public_key_n, header_substrs, body_substrs, &public_input_path).await;
        }
        Commands::GenEVMVerifier {
            params_path,
            circuit_config_path,
            vk_path,
            bytecode_path,
            solidity_path,
        } => gen_evm_verifier::<DefaultEmailVerifyCircuit<Fr>>(&params_path, &circuit_config_path, &vk_path, &bytecode_path, &solidity_path)
            .await
            .unwrap(),
        Commands::GenAggEVMVerifier {
            agg_params_path,
            app_circuit_config_path,
            agg_circuit_config_path,
            vk_path,
            bytecode_path,
            solidity_path,
        } => gen_agg_evm_verifier(
            &agg_params_path,
            &app_circuit_config_path,
            &agg_circuit_config_path,
            &vk_path,
            &bytecode_path,
            &solidity_path,
        )
        .await
        .unwrap(),
        Commands::EVMVerifyApp {
            circuit_config_path,
            bytecode_path,
            proof_path,
            public_input_path,
        } => {
            set_var(EMAIL_VERIFY_CONFIG_ENV, &circuit_config_path);
            let instances = get_instances_from_default_public_input(&public_input_path);
            evm_verify_app(&circuit_config_path, &bytecode_path, &proof_path, instances).unwrap()
        }
        Commands::EVMVerifyAgg {
            app_circuit_config_path,
            agg_circuit_config_path,
            bytecode_path,
            proof_path,
            acc_path,
            public_input_path,
        } => {
            set_var(EMAIL_VERIFY_CONFIG_ENV, &app_circuit_config_path);
            set_var(VERIFY_CONFIG_KEY, &agg_circuit_config_path);
            let instances = get_agg_instances_from_default_public_input(&public_input_path, &acc_path);
            evm_verify_agg(&app_circuit_config_path, &agg_circuit_config_path, &bytecode_path, &proof_path, instances).unwrap()
        }
        Commands::GenRegexFiles {
            decomposed_regex_config_path,
            regex_dir_path,
            regex_files_prefix,
        } => gen_regex_files(&decomposed_regex_config_path, &regex_dir_path, &regex_files_prefix).unwrap(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultEmailVerifyPublicInput {
    pub headerhash: String,
    pub public_key_n_bytes: String,
    pub header_starts: Vec<usize>,
    pub header_substrs: Vec<String>,
    pub body_starts: Vec<usize>,
    pub body_substrs: Vec<String>,
}

async fn gen_default_public_input(
    headerhash: Vec<u8>,
    public_key_n: BigUint,
    header_substrs: Vec<Option<(usize, String)>>,
    body_substrs: Vec<Option<(usize, String)>>,
    public_input_path: &str,
) {
    // let (circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(email_path).await;
    let mut header_starts_vec = vec![];
    let mut header_substrs_vec = vec![];
    for s in header_substrs.into_iter() {
        if let Some(s) = s {
            header_starts_vec.push(s.0);
            header_substrs_vec.push(s.1);
        }
    }
    let mut body_starts_vec = vec![];
    let mut body_substrs_vec = vec![];
    for s in body_substrs.into_iter() {
        if let Some(s) = s {
            body_starts_vec.push(s.0);
            body_substrs_vec.push(s.1);
        }
    }
    let public_input = DefaultEmailVerifyPublicInput {
        headerhash: format!("0x{}", hex::encode(&headerhash)),
        public_key_n_bytes: format!("0x{}", hex::encode(&public_key_n.to_bytes_le())),
        header_starts: header_starts_vec,
        header_substrs: header_substrs_vec,
        body_starts: body_starts_vec,
        body_substrs: body_substrs_vec,
    };
    {
        let public_input_str = serde_json::to_string(&public_input).unwrap();
        let mut file = File::create(public_input_path).expect("public_input_path creation failed");
        write!(file, "{}", public_input_str).unwrap();
        file.flush().unwrap();
    }
}

async fn gen_circuit_from_email_path(email_path: &str) -> (DefaultEmailVerifyCircuit<Fr>, Vec<u8>, BigUint, Vec<Option<(usize, String)>>, Vec<Option<(usize, String)>>) {
    let email_bytes = {
        let mut f = File::open(email_path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };
    println!("email {}", String::from_utf8(email_bytes.clone()).unwrap());
    let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
    let headerhash = Sha256::digest(&canonicalized_header).to_vec();
    let public_key_n = {
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        match resolve_public_key(&logger, &email_bytes).await.unwrap() {
            cfdkim::DkimPublicKey::Rsa(_pk) => BigUint::from_radix_le(&_pk.n().clone().to_radix_le(16), 16).unwrap(),
            _ => {
                panic!("Only RSA keys are supported.");
            }
        }
    };
    let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
    let public_key = RSAPublicKey::<Fr>::new(Value::known(public_key_n.clone()), e);
    let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
    let header_str = String::from_utf8(canonicalized_header.clone()).unwrap();
    let body_str = String::from_utf8(canonicalized_body.clone()).unwrap();
    let config_params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
    let header_config = config_params.header_config.expect("header_config is required");
    let body_config = config_params.body_config.expect("body_config is required");
    let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_config.substr_regexes, body_config.substr_regexes);
    let circuit = DefaultEmailVerifyCircuit {
        header_bytes: canonicalized_header,
        body_bytes: canonicalized_body,
        public_key,
        signature,
    };
    (circuit, headerhash, public_key_n, header_substrs, body_substrs)
}

fn get_instances_from_default_public_input(public_input_path: &str) -> Vec<Fr> {
    let public_input = serde_json::from_reader::<File, DefaultEmailVerifyPublicInput>(File::open(public_input_path).unwrap()).unwrap();
    let config_params = read_default_circuit_config_params();
    let header_config = config_params.header_config.expect("header_config is required");
    let body_config = config_params.body_config.expect("body_config is required");
    let headerhash = hex::decode(&public_input.headerhash[2..]).unwrap();
    let public_key_n_bytes = hex::decode(&public_input.public_key_n_bytes[2..]).unwrap();
    let header_substrs = public_input
        .header_starts
        .into_iter()
        .zip(public_input.header_substrs.into_iter())
        .map(|(start, substr)| Some((start, substr)))
        .collect_vec();
    let body_substrs = public_input
        .body_starts
        .into_iter()
        .zip(public_input.body_substrs.into_iter())
        .map(|(start, substr)| Some((start, substr)))
        .collect_vec();
    let public_hash_input = get_email_circuit_public_hash_input(
        &headerhash,
        &public_key_n_bytes,
        header_substrs,
        body_substrs,
        header_config.max_byte_size,
        body_config.max_byte_size,
    );
    let public_hash: Vec<u8> = Sha256::digest(&public_hash_input).to_vec();
    let public_fr = {
        let lo = Fr::from_u128(u128::from_le_bytes(public_hash[0..16].try_into().unwrap()));
        let mut hi_bytes = [0; 16];
        for idx in 0..15 {
            hi_bytes[idx] = public_hash[16 + idx];
        }
        let hi = Fr::from_u128(u128::from_le_bytes(hi_bytes));
        hi * Fr::from(2).pow_const(128) + lo
    };
    vec![public_fr]
}

fn get_agg_instances_from_default_public_input(public_input_path: &str, acc_path: &str) -> Vec<Fr> {
    let acc = {
        let hex = fs::read_to_string(acc_path).unwrap();
        hex::decode(&hex[2..])
            .unwrap()
            .chunks(32)
            .map(|bytes| {
                let mut bytes = bytes.to_vec();
                bytes.reverse();
                Fr::from_bytes(bytes[..].try_into().unwrap()).unwrap()
            })
            .collect_vec()
    };
    assert_eq!(acc.len(), NUM_ACC_INSTANCES);
    let public_fr = get_instances_from_default_public_input(public_input_path);
    vec![acc, public_fr].concat()
}
