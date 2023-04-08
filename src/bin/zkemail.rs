use base64::prelude::{Engine as _, BASE64_STANDARD};
use cfdkim::{canonicalize_signed_email, resolve_public_key};
use clap::{Parser, Subcommand};
use fancy_regex::Regex;
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, Error, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::Params;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use halo2_zk_email::*;
use hex;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Pow;
use rand::thread_rng;
use rsa::PublicKeyParts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use std::env::set_var;
use std::fmt::format;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use tokio::macros::*;

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
        app_k: u32,
        /// k parameter for the circuit aggregating the proofs of the one email verification circuit.
        #[arg(long)]
        app_to_agg_k: Option<u32>,
        /// k parameter for the circuit aggregating the proofs of the aggregation circuit.
        #[arg(long)]
        agg_to_agg_k: Option<u32>,
        /// setup parameters directory
        #[arg(short, long)]
        params_dir: String,
    },
    /// Generate a proving key and a verifying key.
    GenKeys {
        /// setup parameters directory
        #[arg(short, long)]
        params_dir: String,
        /// email verification circuit configure file
        #[arg(short, long)]
        app_circuit_config: String,
        /// app->agg circuit configure file
        #[arg(short, long)]
        app_to_agg_circuit_config: String,
        /// agg->agg circuit configure file
        #[arg(short, long)]
        agg_to_agg_circuit_config: String,
        /// log2(the number of aggregated email proofs)
        #[arg(short, long)]
        log2_proofs: u32,
        /// proving keys directory
        #[arg(long)]
        pks_dir: String,
        /// verifying key file
        #[arg(long)]
        vk: String,
    },
    Prove {
        /// setup parameters directory
        #[arg(short, long)]
        params_dir: String,
        /// email verification circuit configure file
        #[arg(short, long)]
        app_circuit_config: String,
        /// app->agg circuit configure file
        #[arg(short, long)]
        app_to_agg_circuit_config: String,
        /// agg->agg circuit configure file
        #[arg(short, long)]
        agg_to_agg_circuit_config: String,
        /// proving keys directory
        #[arg(long)]
        pks_dir: String,
        /// emails directory
        #[arg(short, long)]
        emails_dir: String,
        /// log2(the number of aggregated email proofs)
        #[arg(short, long)]
        log2_proofs: u32,
        /// output proof file
        #[arg(long)]
        proof: String,
        /// output accumulator file
        #[arg(long)]
        acc: String,
    },
    GenEVMVerifier {
        /// setup parameters directory
        #[arg(short, long)]
        params_dir: String,
        /// verifying key file
        #[arg(long)]
        vk: String,
        /// log2(the number of aggregated email proofs)
        #[arg(short, long)]
        log2_proofs: u32,
        /// evm verifier file
        #[arg(short, long)]
        evm_verifier: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenParams {
            params_dir,
            app_k,
            app_to_agg_k,
            agg_to_agg_k,
        } => gen_params(&params_dir, app_k, app_to_agg_k, agg_to_agg_k).unwrap(),
        Commands::GenKeys {
            params_dir,
            app_circuit_config,
            app_to_agg_circuit_config,
            agg_to_agg_circuit_config,
            log2_proofs,
            pks_dir,
            vk,
        } => gen_keys(
            &params_dir,
            &app_circuit_config,
            &app_to_agg_circuit_config,
            &agg_to_agg_circuit_config,
            log2_proofs,
            &pks_dir,
            &vk,
        )
        .unwrap(),
        Commands::Prove {
            params_dir,
            app_circuit_config,
            app_to_agg_circuit_config,
            agg_to_agg_circuit_config,
            pks_dir,
            emails_dir,
            log2_proofs,
            proof,
            acc,
        } => prove_multi_evm(
            &params_dir,
            &app_circuit_config,
            &app_to_agg_circuit_config,
            &agg_to_agg_circuit_config,
            &pks_dir,
            &emails_dir,
            log2_proofs,
            &proof,
            &acc,
        )
        .await
        .unwrap(),
        Commands::GenEVMVerifier {
            params_dir,
            vk,
            log2_proofs,
            evm_verifier,
        } => gen_evm_verifier(&params_dir, &vk, log2_proofs, &evm_verifier).unwrap(),
    }
}
