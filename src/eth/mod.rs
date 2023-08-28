// use crate::snark_verifier_sdk::*;
use crate::config_params::default_config_params;
use crate::*;
use ethereum_types::{Address, H256, U256};
use ethers::solc::artifacts::Contract;
use ethers::solc::{CompilerInput, EvmVersion, Solc};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Bytes, TransactionRequest};
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
use revm::precompile::B160;
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
use std::os::unix::prelude::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
pub mod gen_verifier;
use crate::eth::gen_verifier::*;
use ethers::abi::{encode, Abi, Function, Param, ParamType, Token, Tokenize};
use ethers::contract::ContractFactory;
use ethers::core::k256::ecdsa::SigningKey;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::Signer;
use ethers::{
    prelude::{abigen, LocalWallet, Wallet},
    utils::{Anvil, AnvilInstance},
};
// use revm::{
//     primitives::{CreateScheme, ExecutionResult, Output, TransactTo, TxEnv},
//     InMemoryDB, EVM,
// };
abigen!(EmailVerifier, "./src/eth/EmailVerifier.abi");

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeployParamsJson {
    max_transcript_addr: u32,
    num_func_contracts: usize,
}

// original: https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L40
pub type EthersClient = Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>;

// original: https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L58-L86
pub async fn setup_eth_backend() -> AnvilInstance {
    // Launch anvil
    let anvil = Anvil::new().arg("--gas-limit").arg("100000000").spawn();
    anvil
}

// original: https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L58-L86
pub async fn setup_eth_client(anvil: &AnvilInstance) -> EthersClient {
    // Launch anvil
    // let anvil = Anvil::new().spawn();
    // Instantiate the wallet
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    // let rpc_url = Some("http://localhost:8545");

    let endpoint = anvil.endpoint();
    println!("endpoint {}", endpoint);
    // let endpoint: &str = "http://localhost:8545";
    // Connect to the network
    let provider = Provider::<Http>::try_from(endpoint)
        .expect("fail to construct the provider")
        .interval(Duration::from_millis(10u64));

    // let chain_id = provider.get_chainid().await.unwrap();

    // Instantiate the client with the wallet
    let client = Arc::new(SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id())));

    client
}

// pub async fn deploy_and_call_verifiers(sols_dir: &PathBuf, runs: Option<usize>, proofs: &[&[u8]], instance: &DefaultEmailVerifyPublicInput) {
//     // let mut evm = EVM {
//     //     env: Default::default(),
//     //     db: Some(InMemoryDB::default()),
//     // };
//     let anvil = setup_eth_backend().await;
//     let client = setup_eth_client(&anvil).await;
//     let runs = runs.unwrap_or(1);
//     let config_params = default_config_params();
//     let mut gas_sum = U256::zero();
//     let (sha2_header_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "sha2_header", runs).await;
//     gas_sum += gas;
//     let (sign_verify_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "sign_verify", runs).await;
//     gas_sum += gas;
//     let (regex_header_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "regex_header", runs).await;
//     gas_sum += gas;
//     let mut sha2_header_masked_chars_addr = Address::zero();
//     let mut sha2_header_substr_ids_addr = Address::zero();
//     let mut header_expose_substrs = false;
//     let mut gas = U256::zero();
//     let max_header_bytes = U256::from(config_params.header_config.as_ref().unwrap().max_variable_byte_size);
//     if config_params.header_config.as_ref().unwrap().expose_substrs.unwrap_or(false) {
//         (sha2_header_masked_chars_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "sha2_header_masked_chars", runs).await;
//         gas_sum += gas;
//         (sha2_header_substr_ids_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "sha2_header_substr_ids", runs).await;
//         gas_sum += gas;
//         header_expose_substrs = true;
//     }
//     // let (
//     //     mut regex_bodyhash_addr,
//     //     mut chars_shift_bodyhash_addr,
//     //     mut sha2_body_addr,
//     //     mut base64_addr,
//     //     mut regex_body_addr,
//     //     mut sha2_body_masked_chars_addr,
//     //     mut sha2_body_substr_ids_addr,
//     // ) = ([0; 20], [0; 20], [0; 20], [0; 20], [0; 20], [0; 20], [0; 20]);
//     let (
//         mut regex_bodyhash_addr,
//         mut chars_shift_bodyhash_addr,
//         mut sha2_body_addr,
//         mut base64_addr,
//         mut regex_body_addr,
//         mut sha2_body_masked_chars_addr,
//         mut sha2_body_substr_ids_addr,
//     ) = (
//         Address::zero(),
//         Address::zero(),
//         Address::zero(),
//         Address::zero(),
//         Address::zero(),
//         Address::zero(),
//         Address::zero(),
//     );
//     let mut body_enable = false;
//     let mut body_expose_substrs = false;
//     let mut max_body_bytes = U256::zero();
//     if let Some(body_config) = config_params.body_config.as_ref() {
//         body_enable = true;
//         (regex_bodyhash_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "regex_bodyhash", runs).await;
//         gas_sum += gas;
//         (chars_shift_bodyhash_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "chars_shift_bodyhash", runs).await;
//         gas_sum += gas;
//         (sha2_body_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "sha2_body", runs).await;
//         gas_sum += gas;
//         (base64_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "base64", runs).await;
//         gas_sum += gas;
//         (regex_body_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "regex_body", runs).await;
//         gas_sum += gas;
//         max_body_bytes = U256::from(body_config.max_variable_byte_size);
//         if body_config.expose_substrs.unwrap_or(false) {
//             (sha2_body_masked_chars_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "sha2_body_masked_chars", runs).await;
//             gas_sum += gas;
//             (sha2_body_substr_ids_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, "sha2_body_substr_ids", runs).await;
//             gas_sum += gas;
//             body_expose_substrs = true;
//         }
//     }
//     // let email_verify_args = (
//     //     Address::from_slice(&sha2_header_addr),
//     //     Address::from_slice(&sign_verify_addr),
//     //     Address::from_slice(&regex_header_addr),
//     //     Address::from_slice(&sha2_header_masked_chars_addr),
//     //     Address::from_slice(&sha2_header_substr_ids_addr),
//     //     Address::from_slice(&regex_bodyhash_addr),
//     //     Address::from_slice(&chars_shift_bodyhash_addr),
//     //     Address::from_slice(&sha2_body_addr),
//     //     Address::from_slice(&base64_addr),
//     //     Address::from_slice(&regex_body_addr),
//     //     Address::from_slice(&sha2_body_masked_chars_addr),
//     //     Address::from_slice(&sha2_body_substr_ids_addr),
//     //     header_expose_substrs,
//     //     body_enable,
//     //     body_expose_substrs,
//     //     max_header_bytes,
//     //     max_body_bytes,
//     // );
//     // let mut email_verify_constructor_args = encode(&[
//     //     Token::Address(Address::from_slice(&sha2_header_addr)),
//     //     Token::Address(Address::from_slice(&sign_verify_addr)),
//     // ]);
//     // email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(Address::from_slice(&regex_header_addr))]);
//     // email_verify_constructor_args = encode(&[
//     //     Token::Bytes(email_verify_constructor_args),
//     //     Token::Address(Address::from_slice(&sha2_header_masked_chars_addr)),
//     // ]);
//     // email_verify_constructor_args = encode(&[
//     //     Token::Bytes(email_verify_constructor_args),
//     //     Token::Address(Address::from_slice(&sha2_header_substr_ids_addr)),
//     // ]);
//     // email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(Address::from_slice(&regex_bodyhash_addr))]);
//     // email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(Address::from_slice(&chars_shift_bodyhash_addr))]);
//     // email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(Address::from_slice(&sha2_body_addr))]);
//     // email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(Address::from_slice(&base64_addr))]);
//     // email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(Address::from_slice(&regex_body_addr))]);
//     // email_verify_constructor_args = encode(&[
//     //     Token::Bytes(email_verify_constructor_args),
//     //     Token::Address(Address::from_slice(&sha2_body_masked_chars_addr)),
//     // ]);
//     // email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(Address::from_slice(&sha2_body_substr_ids_addr))]);
//     let mut email_verify_constructor_args = encode(&[Token::Address(sha2_header_addr), Token::Address(sign_verify_addr)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(regex_header_addr)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(sha2_header_masked_chars_addr)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(sha2_header_substr_ids_addr)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(regex_bodyhash_addr)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(chars_shift_bodyhash_addr)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(sha2_body_addr)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(base64_addr)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(regex_body_addr)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(sha2_body_masked_chars_addr)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Address(sha2_body_substr_ids_addr)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Bool(header_expose_substrs)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Bool(body_enable)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Bool(body_expose_substrs)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Uint(max_header_bytes)]);
//     email_verify_constructor_args = encode(&[Token::Bytes(email_verify_constructor_args), Token::Uint(max_body_bytes)]);
//     // let mut email_verify_constructor_args = encode(&[
//     //     Token::Address(Address::from_slice(&sha2_header_addr)),
//     //     Token::Address(Address::from_slice(&sign_verify_addr)),
//     //     Token::Address(Address::from_slice(&regex_header_addr)),
//     //     Token::Address(Address::from_slice(&sha2_header_masked_chars_addr)),
//     //     Token::Address(Address::from_slice(&sha2_header_substr_ids_addr)),
//     //     Token::Address(Address::from_slice(&regex_bodyhash_addr)),
//     //     Token::Address(Address::from_slice(&chars_shift_bodyhash_addr)),
//     //     Token::Address(Address::from_slice(&sha2_body_addr)),
//     //     Token::Address(Address::from_slice(&base64_addr)),
//     //     Token::Address(Address::from_slice(&regex_body_addr)),
//     //     Token::Address(Address::from_slice(&sha2_body_masked_chars_addr)),
//     //     Token::Address(Address::from_slice(&sha2_body_substr_ids_addr)),
//     //     Token::Bool(header_expose_substrs),
//     //     Token::Bool(body_enable),
//     //     Token::Bool(body_expose_substrs),
//     //     Token::Uint(max_header_bytes),
//     //     Token::Uint(max_body_bytes),
//     // ]);
//     let (email_verifier, gas) = deploy_verifier_via_solidity(
//         &client,
//         sols_dir.join("EmailVerifier.sol"),
//         "EmailVerifier",
//         Bytes::from(email_verify_constructor_args),
//         Some(runs),
//     )
//     .await;
//     gas_sum += gas;
//     println!("total deploy gas {}", gas_sum);

//     let verifier = EmailVerifier::new(email_verifier, client.clone());
//     let instance = EmailProofInstance {
//         header_bytes_commit: U256::from_str_radix(&instance.header_bytes_commit, 10).unwrap(),
//         header_hash_commit: U256::from_str_radix(&instance.header_hash_commit, 10).unwrap(),
//         public_key_n_hash: U256::from_str_radix(&instance.public_key_n_hash, 10).unwrap(),
//         tag: U256::from_str_radix(&instance.tag, 10).unwrap(),
//         header_masked_chars_commit: U256::from_str_radix(&instance.header_masked_chars_commit, 10).unwrap(),
//         header_substr_ids_commit: U256::from_str_radix(&instance.header_substr_ids_commit, 10).unwrap(),
//         header_substrs: instance.header_substrs.clone(),
//         header_substr_idxes: instance.header_substr_idxes.iter().map(|idx| U256::from(*idx)).collect_vec(),
//         bodyhash_masked_chars_commit: instance
//             .bodyhash_masked_chars_commit
//             .as_ref()
//             .map(|s| U256::from_str_radix(s, 10).unwrap())
//             .unwrap_or(U256::zero()),
//         bodyhash_substr_ids_commit: instance
//             .bodyhash_substr_ids_commit
//             .as_ref()
//             .map(|s| U256::from_str_radix(s, 10).unwrap())
//             .unwrap_or(U256::zero()),
//         bodyhash_base_64_commit: instance
//             .bodyhash_base64_commit
//             .as_ref()
//             .map(|s| U256::from_str_radix(s, 10).unwrap())
//             .unwrap_or(U256::zero()),
//         body_bytes_commit: instance.body_bytes_commit.as_ref().map(|s| U256::from_str_radix(s, 10).unwrap()).unwrap_or(U256::zero()),
//         bodyhash_commit: instance.bodyhash_commit.as_ref().map(|s| U256::from_str_radix(s, 10).unwrap()).unwrap_or(U256::zero()),
//         body_masked_chars_commit: instance
//             .body_masked_chars_commit
//             .as_ref()
//             .map(|s| U256::from_str_radix(s, 10).unwrap())
//             .unwrap_or(U256::zero()),
//         body_substr_ids_commit: instance
//             .body_substr_ids_commit
//             .as_ref()
//             .map(|s| U256::from_str_radix(s, 10).unwrap())
//             .unwrap_or(U256::zero()),
//         body_substrs: instance.body_substrs.clone().unwrap_or(vec![]),
//         body_substr_idxes: instance.body_substr_idxes.clone().unwrap_or(vec![]).iter().map(|idx| U256::from(*idx)).collect_vec(),
//     };
//     println!("instance {:?}", instance);
//     let proofs = proofs.into_iter().map(|proof| Bytes::from(proof.to_vec())).collect_vec();
//     let result = verifier.verify_email(instance.clone(), proofs.clone()).call().await;
//     println!("result {:?}", result);
//     let call = verifier.method::<_, ()>("verifyEmail", (instance.clone(), proofs.clone())).unwrap();
//     println!("estimated gas {:?}", call.estimate_gas().await.unwrap());
//     // drop(anvil);

//     // let proofs = proofs.into_iter().map(|proof| Token::Bytes(proof.to_vec())).collect_vec();
//     // let func = Function {
//     //     name: "verifyEmail".to_owned(),
//     //     inputs: vec![
//     //         Param {
//     //             name: "instance".to_owned(),
//     //             kind: ParamType::Tuple(vec![
//     //                 ParamType::Uint(256),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Array(Box::new(ParamType::String)),
//     //                 ParamType::Array(Box::new(ParamType::Uint(256))),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Uint(256),
//     //                 ParamType::Array(Box::new(ParamType::String)),
//     //                 ParamType::Array(Box::new(ParamType::Uint(256))),
//     //             ]),
//     //             internal_type: Some("struct EmailVerifier.EmailProofInstance".to_string()),
//     //         },
//     //         Param {
//     //             name: "proofs".to_owned(),
//     //             kind: ParamType::Array(Box::new(ParamType::Bytes)),
//     //             internal_type: Some("bytes[]".to_string()),
//     //         },
//     //     ],
//     //     outputs: vec![Param {
//     //         name: "".to_owned(),
//     //         kind: ParamType::Bool,
//     //         internal_type: Some("bool".to_string()),
//     //     }],
//     //     constant: None,
//     //     state_mutability: ethers::abi::StateMutability::View,
//     // };
//     // let encoded = func
//     //     .encode_input(&[
//     //         Token::Tuple(vec![
//     //             Token::Uint(U256::from_str_radix(&instance.header_bytes_commit, 10).unwrap()),
//     //             Token::Uint(U256::from_str_radix(&instance.header_hash_commit, 10).unwrap()),
//     //             Token::Uint(U256::from_str_radix(&instance.public_key_n_hash, 10).unwrap()),
//     //             Token::Uint(U256::from_str_radix(&instance.tag, 10).unwrap()),
//     //             Token::Uint(U256::from_str_radix(&instance.header_masked_chars_commit, 10).unwrap()),
//     //             Token::Uint(U256::from_str_radix(&instance.header_substr_ids_commit, 10).unwrap()),
//     //             Token::Array(instance.header_substrs.iter().map(|s| Token::String(s.clone())).collect_vec()),
//     //             Token::Array(instance.header_substr_idxes.iter().map(|idx| Token::Uint(U256::from(idx.clone()))).collect_vec()),
//     //             instance
//     //                 .bodyhash_masked_chars_commit
//     //                 .as_ref()
//     //                 .map(|s| Token::Uint(U256::from_str_radix(&s, 10).unwrap()))
//     //                 .unwrap_or(Token::Uint(U256::zero())),
//     //             instance
//     //                 .bodyhash_substr_ids_commit
//     //                 .as_ref()
//     //                 .map(|s| Token::Uint(U256::from_str_radix(&s, 10).unwrap()))
//     //                 .unwrap_or(Token::Uint(U256::zero())),
//     //             instance
//     //                 .bodyhash_base64_commit
//     //                 .as_ref()
//     //                 .map(|s| Token::Uint(U256::from_str_radix(&s, 10).unwrap()))
//     //                 .unwrap_or(Token::Uint(U256::zero())),
//     //             instance
//     //                 .body_bytes_commit
//     //                 .as_ref()
//     //                 .map(|s| Token::Uint(U256::from_str_radix(&s, 10).unwrap()))
//     //                 .unwrap_or(Token::Uint(U256::zero())),
//     //             instance
//     //                 .bodyhash_commit
//     //                 .as_ref()
//     //                 .map(|s| Token::Uint(U256::from_str_radix(&s, 10).unwrap()))
//     //                 .unwrap_or(Token::Uint(U256::zero())),
//     //             instance
//     //                 .body_masked_chars_commit
//     //                 .as_ref()
//     //                 .map(|s| Token::Uint(U256::from_str_radix(&s, 10).unwrap()))
//     //                 .unwrap_or(Token::Uint(U256::zero())),
//     //             instance
//     //                 .body_substr_ids_commit
//     //                 .as_ref()
//     //                 .map(|s| Token::Uint(U256::from_str_radix(&s, 10).unwrap()))
//     //                 .unwrap_or(Token::Uint(U256::zero())),
//     //             Token::Array(instance.body_substrs.as_ref().unwrap_or(&vec![]).iter().map(|s| Token::String(s.clone())).collect_vec()),
//     //             Token::Array(
//     //                 instance
//     //                     .body_substr_idxes
//     //                     .as_ref()
//     //                     .unwrap_or(&vec![])
//     //                     .iter()
//     //                     .map(|idx| Token::Uint(U256::from(idx.clone())))
//     //                     .collect_vec(),
//     //             ),
//     //         ]),
//     //         Token::Array(proofs),
//     //     ])
//     //     .unwrap();
//     // // println!("encoded {:?}", encoded);

//     // evm.env.tx = TxEnv {
//     //     gas_limit: u64::MAX,
//     //     transact_to: TransactTo::Call(email_verifier.into()),
//     //     data: encoded.into(),
//     //     ..Default::default()
//     // };
//     // let result = evm.transact_commit().unwrap();
//     // match result {
//     //     ExecutionResult::Success { gas_used, output, .. } => {
//     //         println!("gas_used: {}", gas_used);
//     //         if let Output::Call(output) = output {
//     //             println!("output: {:?}", output);
//     //         } else {
//     //             panic!("output is not bytes")
//     //         }
//     //     }
//     //     ExecutionResult::Revert { gas_used, output } => panic!("Contract call transaction reverts with gas_used {gas_used} and output {:#x}", output),
//     //     ExecutionResult::Halt { reason, gas_used } => panic!("Contract call transaction halts unexpectedly with gas_used {gas_used} and reason {:?}", reason),
//     // }
// }

pub async fn deploy_and_call_verifiers(sols_dir: &PathBuf, runs: Option<usize>, proof: &[u8], instance: &DefaultEmailVerifyPublicInput) {
    // let mut evm = EVM {
    //     env: Default::default(),
    //     db: Some(InMemoryDB::default()),
    // };
    let anvil = setup_eth_backend().await;
    let client = setup_eth_client(&anvil).await;
    let runs = runs.unwrap_or(1);
    let config_params = default_config_params();
    let mut gas_sum = U256::zero();
    let (base_addr, gas) = deploy_verifier_base_and_funcs(&client, sols_dir, runs).await;
    gas_sum += gas;

    let max_header_bytes = config_params.header_config.as_ref().unwrap().max_variable_byte_size;
    let max_body_bytes = config_params.body_config.as_ref().unwrap().max_variable_byte_size;
    let (email_verifier, gas) = deploy_verifier_via_solidity(
        &client,
        sols_dir.join("EmailVerifier.sol"),
        "EmailVerifier",
        (
            Token::Address(base_addr),
            Token::Uint(U256::from(max_header_bytes)),
            Token::Uint(U256::from(max_body_bytes)),
        ),
        Some(runs),
    )
    .await;
    gas_sum += gas;
    println!("total deploy gas {}", gas_sum);
    println!("address {:?}", Address::from(email_verifier));

    let verifier = EmailVerifier::new(email_verifier, client.clone());
    let instance = encode(&[
        Token::Uint(U256::from_str_radix(&instance.header_hash_commit, 10).unwrap()),
        Token::Uint(U256::from_str_radix(&instance.public_key_hash, 10).unwrap()),
        Token::Array(instance.header_substrs.iter().map(|s| Token::String(s.clone())).collect_vec()),
        Token::Array(instance.header_starts.iter().map(|idx| Token::Uint(U256::from(idx.clone()))).collect_vec()),
        Token::Array(instance.body_substrs.iter().map(|s| Token::String(s.clone())).collect_vec()),
        Token::Array(instance.body_starts.iter().map(|idx| Token::Uint(U256::from(idx.clone()))).collect_vec()),
    ]);
    // EmailProofInstance {
    //     header_hash_commit: U256::from_str_radix(&instance.header_hash_commit, 10).unwrap(),
    //     public_key_hash: U256::from_str_radix(&instance.public_key_hash, 10).unwrap(),
    //     header_substrs: instance.header_substrs.clone(),
    //     header_substr_starts: instance.header_starts.iter().map(|idx| U256::from(*idx)).collect_vec(),
    //     body_substrs: instance.body_substrs.clone(),
    //     body_substr_starts: instance.body_starts.iter().map(|idx| U256::from(*idx)).collect_vec(),
    // };
    let proof = Bytes::from(proof.to_vec());
    // println!("proof {:?}", proof);
    // Bytes::from(proof.to_vec());
    verifier.verify_email(Bytes::from(instance.clone()), proof.clone()).call().await.unwrap();
    let call = verifier.method::<_, ()>("verifyEmail", (Bytes::from(instance.clone()), proof.clone())).unwrap();
    println!("estimated gas {:?}", call.estimate_gas().await.unwrap());
    // drop(anvil);

    // let proofs = proofs.into_iter().map(|proof| Token::Bytes(proof.to_vec())).collect_vec();
    // let func = Function {
    //     name: "verifyEmail".to_owned(),
    //     inputs: vec![
    //         Param {
    //             name: "instance".to_owned(),
    //             kind: ParamType::Bytes,
    //             internal_type: Some("bytes".to_string()),
    //         },
    //         Param {
    //             name: "proofs".to_owned(),
    //             kind: ParamType::Bytes,
    //             internal_type: Some("bytes".to_string()),
    //         },
    //     ],
    //     outputs: vec![],
    //     constant: None,
    //     state_mutability: ethers::abi::StateMutability::View,
    // };
    // let encoded = func.encode_input(&[Token::Bytes(instance), Token::Bytes(proof.to_vec())]).unwrap();
    // let tx: TypedTransaction = TransactionRequest::default()
    //     .to(email_verifier)
    //     .from(client.address())
    //     .data(encoded)
    //     .chain_id(anvil.chain_id())
    //     .gas(153526000)
    //     .into();
    // println!("tx {:?}", tx);
    // let result = client.send_transaction(tx, None).await;
    // println!("result {:?}", result);
}

async fn deploy_verifier_base_and_funcs(client: &EthersClient, sols_dir: &PathBuf, runs: usize) -> (Address, U256) {
    let deploy_params =
        serde_json::from_reader::<_, DeployParamsJson>(File::open(&sols_dir.join("deploy_params.json")).expect(&format!("deploy_params.json in {:?} cannot open", sols_dir)))
            .expect(&format!("fail to convert deploy_params.json in {:?}", sols_dir));
    let mut func_addrs = vec![];
    let mut gas_sum = U256::zero();
    for idx in 0..deploy_params.num_func_contracts {
        let (func_addr, gas) = deploy_verifier_via_solidity(client, sols_dir.join(format!("VerifierFunc{}.sol", idx)), &format!("VerifierFunc{}", idx), (), Some(runs)).await;
        gas_sum += gas;
        func_addrs.push(Address::from(func_addr));
    }
    let base_args = (func_addrs, U256::from(deploy_params.max_transcript_addr));
    let (base_addr, gas) = deploy_verifier_via_solidity(client, sols_dir.join("VerifierBase.sol"), "VerifierBase", base_args, Some(runs)).await;
    gas_sum += gas;
    (base_addr, gas_sum)
}

// original: https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L89-L103
async fn deploy_verifier_via_solidity<T: Tokenize>(
    client: &EthersClient,
    sol_code_path: PathBuf,
    contract_name: &str,
    args: T,
    runs: Option<usize>,
) -> (ethers::types::Address, U256) {
    let (abi, bytecode, runtime_bytecode) = get_contract_artifacts(&sol_code_path, contract_name, runs);
    let factory = get_sol_contract_factory(abi.clone(), bytecode, runtime_bytecode, client.clone());
    let (contract, receipt) = factory
        .deploy(args)
        .expect("invalid deploy params")
        .send_with_receipt()
        .await
        .expect("failed to deploy the factory");
    println!("solidity code path: {:?}", &sol_code_path);
    println!("gas used: {:?}", receipt.gas_used);
    (contract.address(), receipt.gas_used.unwrap())
}

// original: https://github.com/zkonduit/snark-verifier/blob/main/snark-verifier/src/loader/evm/util/executor.rs
// async fn deploy_verifier_via_solidity<T: Tokenize>(evm: &mut EVM<InMemoryDB>, sol_code_path: PathBuf, contract_name: &str, args: T, runs: Option<usize>) -> (B160, u64) {
//     let (abi, bytecode, runtime_bytecode) = get_contract_artifacts(&sol_code_path, contract_name, runs);
//     let params = args.into_tokens();
//     if let Some(constructor) = abi.constructor() {
//         println!("param types {:?}", constructor.inputs.iter().map(|p| p.kind.clone()).collect_vec())
//     }
//     let data: Bytes = match (abi.constructor(), params.is_empty()) {
//         (None, false) => panic!("constructor is not defined but the arg is not empty"),
//         (None, true) => bytecode.clone(),
//         (Some(constructor), _) => constructor.encode_input(bytecode.to_vec(), &params).expect("invalid constructor parameters").into(),
//     };
//     // let factory = get_sol_contract_factory(abi.clone(), bytecode, runtime_bytecode, client);
//     // let (contract, receipt) = factory
//     //     .deploy(args)
//     //     .expect("invalid deploy params")
//     //     .send_with_receipt()
//     //     .await
//     //     .expect("failed to deploy the factory");
//     println!("solidity code path: {:?}", &sol_code_path);
//     println!("deployed data: {}", hex::encode(&data.0));
//     // println!("gas used: {:?}", receipt.gas_used);
//     // (contract.address(), receipt.gas_used.unwrap())
//     // let bytecode = compile_sol(&sol_code_path, runs);
//     evm.env.tx = TxEnv {
//         gas_limit: u64::MAX,
//         transact_to: TransactTo::Create(CreateScheme::Create),
//         data: data.0.into(),
//         ..Default::default()
//     };
//     let result = evm.transact_commit().unwrap();
//     let mut gas = 0;
//     let contract = match result {
//         ExecutionResult::Success {
//             output: Output::Create(_, Some(contract)),
//             gas_used,
//             ..
//         } => {
//             gas = gas_used;
//             contract
//         }
//         ExecutionResult::Revert { gas_used, output } => panic!("Contract deployment transaction reverts with gas_used {gas_used} and output {:#x}", output),
//         ExecutionResult::Halt { reason, gas_used } => panic!("Contract deployment transaction halts unexpectedly with gas_used {gas_used} and reason {:?}", reason),
//         _ => unreachable!(),
//     };
//     (contract.into(), gas)
// }

// // original: https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L558-L578
pub fn get_contract_artifacts(sol_code_path: &PathBuf, contract_name: &str, runs: Option<usize>) -> (Abi, Bytes, Bytes) {
    assert!(sol_code_path.exists(), "sol_code_path {:?} does not exist", sol_code_path);
    // Create the compiler input, enabling the optimizer and setting the optimzer runs.
    let input: CompilerInput = if let Some(r) = runs {
        let mut i = CompilerInput::new(&sol_code_path).expect("invalid compiler input")[0].clone().optimizer(r);
        i.settings.optimizer.enable();
        i
    } else {
        CompilerInput::new(&sol_code_path).expect("invalid compiler input")[0].clone()
    };
    let input = input.evm_version(EvmVersion::Paris);
    let compiled = Solc::default().compile(&input).unwrap();
    // println!("compiled {:?}", compiled);
    let (abi, bytecode, runtime_bytecode) = compiled
        .find(contract_name)
        .expect(&format!("could not find contract {} in {:?}", contract_name, &sol_code_path))
        .into_parts_or_default();
    (abi, bytecode, runtime_bytecode)
}

fn get_sol_contract_factory<M: 'static + Middleware>(abi: Abi, bytecode: Bytes, runtime_bytecode: Bytes, client: Arc<M>) -> ContractFactory<M> {
    const MAX_RUNTIME_BYTECODE_SIZE: usize = 24577;
    let size = runtime_bytecode.len();
    println!("bytecode size {}", size);
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
