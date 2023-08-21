// use crate::snark_verifier_sdk::*;
use crate::config_params::default_config_params;
use crate::*;
use ethereum_types::{Address, H256, U256};
use ethers::solc::artifacts::Contract;
use ethers::solc::{CompilerInput, Solc};
use ethers::types::Bytes;
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::halo2_proofs::plonk::{Error, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::SerdeFormat;
use hex;
use itertools::Itertools;
use num_bigint::BigUint;
use rand::rngs::OsRng;
use rand::thread_rng;
use regex_simple::Regex;
use rsa::PublicKeyParts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier::loader::evm::{compile_yul, EvmLoader, ExecutorBuilder};
use snark_verifier::loader::LoadedScalar;
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier::system::halo2::{compile, Config};
use snark_verifier::verifier::PlonkVerifier;
use snark_verifier_sdk::evm::{encode_calldata, evm_verify, gen_evm_proof_shplonk};
use snark_verifier_sdk::halo2::aggregation::PublicAggregationCircuit;
use snark_verifier_sdk::halo2::{gen_proof_shplonk, gen_snark_shplonk};
use snark_verifier_sdk::Plonk;
use snark_verifier_sdk::{gen_pk, CircuitExt, LIMBS};
use std::env::set_var;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
pub mod gen_verifier;
use crate::eth::gen_verifier::*;
use ethers::abi::{Abi, Tokenize};
use ethers::contract::ContractFactory;
use ethers::core::k256::ecdsa::SigningKey;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::Signer;
use ethers::{
    prelude::{abigen, LocalWallet, Wallet},
    utils::{Anvil, AnvilInstance},
};
mod email_verifier_contract;
use email_verifier_contract::{EmailProofInstance, EmailVerifierContract};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeployParamsJson {
    max_transcript_addr: u32,
    num_func_contracts: usize,
}

// original: https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L40
pub type EthersClient = Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>;

// original: https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L58-L86
pub async fn setup_eth_backend(rpc_url: Option<&str>) -> (AnvilInstance, EthersClient) {
    // Launch anvil
    let anvil = Anvil::new().spawn();

    // Instantiate the wallet
    let wallet: LocalWallet = anvil.keys()[0].clone().into();

    let endpoint = if let Some(rpc_url) = rpc_url { rpc_url.to_string() } else { anvil.endpoint() };

    // Connect to the network
    let provider = Provider::<Http>::try_from(endpoint)
        .expect("fail to construct the provider")
        .interval(Duration::from_millis(10u64));

    // Instantiate the client with the wallet
    let client = Arc::new(SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id())));

    (anvil, client)
}

pub async fn verify_evm_proofs(proofs: &[&[u8]], verifier_addr: Address, client: &EthersClient, instance: &EmailVerifyInstancesJson) {
    let verifier = EmailVerifierContract::new(verifier_addr, client.clone());
    let instance = EmailProofInstance {
        header_bytes_commit: U256::from_str_radix(&instance.header_bytes_commit, 10).unwrap(),
        header_hash_commit: U256::from_str_radix(&instance.header_hash_commit, 10).unwrap(),
        public_key_n_hash: U256::from_str_radix(&instance.public_key_n_hash, 10).unwrap(),
        tag: U256::from_str_radix(&instance.tag, 10).unwrap(),
        header_masked_chars_commit: U256::from_str_radix(&instance.header_masked_chars_commit, 10).unwrap(),
        header_substr_ids_commit: U256::from_str_radix(&instance.header_substr_ids_commit, 10).unwrap(),
        header_substrs: instance.header_substrs.clone(),
        header_substr_idxes: instance.header_substr_idxes.iter().map(|idx| U256::from(*idx)).collect_vec(),
        bodyhash_masked_chars_commit: instance
            .bodyhash_masked_chars_commit
            .as_ref()
            .map(|s| U256::from_str_radix(s, 10).unwrap())
            .unwrap_or(U256::zero()),
        bodyhash_substr_ids_commit: instance
            .bodyhash_substr_ids_commit
            .as_ref()
            .map(|s| U256::from_str_radix(s, 10).unwrap())
            .unwrap_or(U256::zero()),
        bodyhash_base_64_commit: instance
            .bodyhash_base64_commit
            .as_ref()
            .map(|s| U256::from_str_radix(s, 10).unwrap())
            .unwrap_or(U256::zero()),
        body_bytes_commit: instance.body_bytes_commit.as_ref().map(|s| U256::from_str_radix(s, 10).unwrap()).unwrap_or(U256::zero()),
        bodyhash_commit: instance.bodyhash_commit.as_ref().map(|s| U256::from_str_radix(s, 10).unwrap()).unwrap_or(U256::zero()),
        body_masked_chars_commit: instance
            .body_masked_chars_commit
            .as_ref()
            .map(|s| U256::from_str_radix(s, 10).unwrap())
            .unwrap_or(U256::zero()),
        body_substr_ids_commit: instance
            .body_substr_ids_commit
            .as_ref()
            .map(|s| U256::from_str_radix(s, 10).unwrap())
            .unwrap_or(U256::zero()),
        body_substrs: instance.body_substrs.clone().unwrap_or(vec![]),
        body_substr_idxes: instance.body_substr_idxes.clone().unwrap_or(vec![]).iter().map(|idx| U256::from(*idx)).collect_vec(),
    };
    let proofs = proofs.into_iter().map(|proof| Bytes::from(proof.to_vec())).collect_vec();
    verifier.verify(instance, proofs).call().await.unwrap();
}

pub async fn deploy_verifiers(sols_dir: &PathBuf, client: &EthersClient, runs: Option<usize>) -> ethers::types::Address {
    let runs = runs.unwrap_or(1);
    let config_params = default_config_params();
    let sha2_header_addr = deploy_verifier_base_and_funcs(sols_dir, "sha2_header", &client, runs).await;
    let sign_verify_addr = deploy_verifier_base_and_funcs(sols_dir, "sign_verify", &client, runs).await;
    let regex_header_addr = deploy_verifier_base_and_funcs(sols_dir, "regex_header", &client, runs).await;
    let mut sha2_header_masked_chars_addr = Address::zero();
    let mut sha2_header_substr_ids_addr = Address::zero();
    let mut header_expose_substrs = false;
    let max_header_bytes = U256::from(config_params.header_config.as_ref().unwrap().max_variable_byte_size);
    if config_params.header_config.as_ref().unwrap().expose_substrs.unwrap_or(false) {
        sha2_header_masked_chars_addr = deploy_verifier_base_and_funcs(sols_dir, "sha2_header_masked_chars", &client, runs).await;
        sha2_header_substr_ids_addr = deploy_verifier_base_and_funcs(sols_dir, "sha2_header_substr_ids", &client, runs).await;
        header_expose_substrs = true;
    }
    let (
        mut regex_bodyhash_addr,
        mut chars_shift_bodyhash_addr,
        mut sha2_body_addr,
        mut base64_addr,
        mut regex_body_addr,
        mut sha2_body_masked_chars_addr,
        mut sha2_body_substr_ids_addr,
    ) = (
        Address::zero(),
        Address::zero(),
        Address::zero(),
        Address::zero(),
        Address::zero(),
        Address::zero(),
        Address::zero(),
    );
    let mut body_enable = false;
    let mut body_expose_substrs = false;
    let mut max_body_bytes = U256::zero();
    if let Some(body_config) = config_params.body_config.as_ref() {
        body_enable = true;
        regex_bodyhash_addr = deploy_verifier_base_and_funcs(sols_dir, "regex_bodyhash", &client, runs).await;
        chars_shift_bodyhash_addr = deploy_verifier_base_and_funcs(sols_dir, "chars_shift_bodyhash", &client, runs).await;
        sha2_body_addr = deploy_verifier_base_and_funcs(sols_dir, "sha2_body", &client, runs).await;
        base64_addr = deploy_verifier_base_and_funcs(sols_dir, "base64", &client, runs).await;
        regex_body_addr = deploy_verifier_base_and_funcs(sols_dir, "regex_body", &client, runs).await;
        max_body_bytes = U256::from(body_config.max_variable_byte_size);
        if body_config.expose_substrs.unwrap_or(false) {
            sha2_body_masked_chars_addr = deploy_verifier_base_and_funcs(sols_dir, "sha2_body_masked_chars", &client, runs).await;
            sha2_body_substr_ids_addr = deploy_verifier_base_and_funcs(sols_dir, "sha2_body_substr_ids", &client, runs).await;
            body_expose_substrs = true;
        }
    }
    let email_verify_args = (
        sha2_header_addr,
        sign_verify_addr,
        regex_header_addr,
        sha2_header_masked_chars_addr,
        sha2_header_substr_ids_addr,
        regex_bodyhash_addr,
        chars_shift_bodyhash_addr,
        sha2_body_addr,
        base64_addr,
        regex_body_addr,
        sha2_body_masked_chars_addr,
        sha2_body_substr_ids_addr,
        header_expose_substrs,
        body_enable,
        body_expose_substrs,
        max_header_bytes,
        max_body_bytes,
    );
    let email_verifier = deploy_verifier_via_solidity(client.clone(), sols_dir.join("EmailVerifier.sol"), "EmailVerifier", email_verify_args, Some(runs)).await;
    email_verifier
}

async fn deploy_verifier_base_and_funcs(sols_dir: &PathBuf, dir_name: &str, client: &EthersClient, runs: usize) -> ethers::types::Address {
    let dir = sols_dir.join(&dir_name);
    let deploy_params = serde_json::from_reader::<_, DeployParamsJson>(File::open(&dir.join("deploy_params.json")).expect(&format!("deploy_params.json in {:?} cannot open", dir)))
        .expect(&format!("fail to convert deploy_params.json in {:?}", dir));
    let mut func_addrs = vec![];
    for idx in 0..deploy_params.num_func_contracts {
        let func_addr = deploy_verifier_via_solidity(
            client.clone(),
            dir.join(format!("VerifierFunc{}.sol", idx)),
            &format!("VerifierFunc{}", idx),
            (),
            Some(runs),
        )
        .await;
        func_addrs.push(func_addr);
    }
    let base_args = (func_addrs, U256::from(deploy_params.max_transcript_addr));
    let base_addr = deploy_verifier_via_solidity(client.clone(), dir.join("VerifierBase.sol"), "VerifierBase", base_args, Some(runs)).await;
    base_addr
}

// original: https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L89-L103
async fn deploy_verifier_via_solidity<T: Tokenize>(client: EthersClient, sol_code_path: PathBuf, contract_name: &str, args: T, runs: Option<usize>) -> ethers::types::Address {
    let (abi, bytecode, runtime_bytecode) = get_contract_artifacts(sol_code_path, contract_name, runs);
    let factory = get_sol_contract_factory(abi, bytecode, runtime_bytecode, client);

    let contract = factory.deploy(args).expect("invalid deploy params").send().await.expect("failed to deploy the factory");
    contract.address()
}

// original: https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L558-L578
pub fn get_contract_artifacts(sol_code_path: PathBuf, contract_name: &str, runs: Option<usize>) -> (Abi, Bytes, Bytes) {
    assert!(sol_code_path.exists());
    // Create the compiler input, enabling the optimizer and setting the optimzer runs.
    let input: CompilerInput = if let Some(r) = runs {
        let mut i = CompilerInput::new(&sol_code_path).expect("invalid compiler input")[0].clone().optimizer(r);
        i.settings.optimizer.enable();
        i
    } else {
        CompilerInput::new(&sol_code_path).expect("invalid compiler input")[0].clone()
    };
    let compiled = Solc::default().compile(&input).unwrap();
    let (abi, bytecode, runtime_bytecode) = compiled
        .find(contract_name)
        .expect(&format!("could not find contract {} in {:?}", contract_name, &sol_code_path))
        .into_parts_or_default();
    (abi, bytecode, runtime_bytecode)
}

fn get_sol_contract_factory<M: 'static + Middleware>(abi: Abi, bytecode: Bytes, runtime_bytecode: Bytes, client: Arc<M>) -> ContractFactory<M> {
    const MAX_RUNTIME_BYTECODE_SIZE: usize = 24577;
    let size = runtime_bytecode.len();
    if size > MAX_RUNTIME_BYTECODE_SIZE {
        // `_runtime_bytecode` exceeds the limit
        panic!(
            "Solidity runtime bytecode size is: {:#?},
            which exceeds 24577 bytes limit.",
            size
        );
    }
    ContractFactory::new(abi, bytecode, client)
}
