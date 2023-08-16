///! A circuit in this example verifies that the email is authenticated and extracts the email address in the "from" field from its header and the substring of "(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+" from its body.
use base64::prelude::{Engine as _, BASE64_STANDARD};
use cfdkim::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fancy_regex::Regex;
use halo2_base::halo2_proofs;
use halo2_base::halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::poly::{
    commitment::{Params, ParamsProver, ParamsVerifier},
    kzg::commitment::ParamsKZG,
};
use halo2_base::halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error, SerdeFormat};
use halo2_base::halo2_proofs::{
    circuit::{floor_planner::V1, Cell, Value},
    dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
    plonk::{Any, Column, Instance, ProvingKey, VerifyingKey},
};
use halo2_base::{gates::range::RangeConfig, utils::PrimeField, Context};
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_regex::defs::{AllstrRegexDef, SubstrRegexDef};
use halo2_regex::vrm::DecomposedRegexConfig;
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use halo2_zk_email::utils::get_email_substrs;
use halo2_zk_email::{evm_prove_app, evm_verify_app, gen_app_key, gen_evm_verifier, gen_params};
use halo2_zk_email::{DefaultEmailVerifyCircuit, DefaultEmailVerifyPublicInput, EMAIL_VERIFY_CONFIG_ENV};
use itertools::Itertools;
use mailparse::parse_mail;
use num_bigint::BigUint;
use rand::rngs::OsRng;
use rand::thread_rng;
use rand::Rng;
use rsa::{PublicKeyParts, RsaPrivateKey};
use sha2::{self, Digest, Sha256};
use snark_verifier_sdk::halo2::{gen_proof, gen_proof_shplonk};
use snark_verifier_sdk::CircuitExt;
use std::env::set_var;
use std::{
    fs::File,
    io::{prelude::*, BufReader, BufWriter},
    path::Path,
};
use tokio::runtime::Runtime;

fn main() {
    // 1. Generate regex-definition text files from the decomposed regex jsons.
    let example_body_decomposed_regex_json = r#"
    {
        "max_byte_size": 128,
        "parts":[
            {
                "is_public": false,
                "regex_def": "email was meant for @",
                "max_size": 21
            },
            {
                "is_public": true,
                "regex_def": "(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+",
                "max_size": 7,
                "solidity": {
                    "type": "String"
                }
            },
            {
                "is_public": false,
                "regex_def": ".",
                "max_size": 1
            },
            {
                "is_public": false,
                "regex_def": "(0|1|2|3|4|5|6|7|8|9|a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|!|\"|#|$|%|&|'|\\(|\\)|\\*|\\+|,|-|.|/|:|;|<|=|>|\\?|@|[|\\\\|]|^|_|`|{|\\||}|~| |\t|\n|\r|\\x0b|\\x0c)*",
                "max_size": 1024
            }
        ]
    }
    "#;
    let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
    regex_bodyhash_decomposed
        .gen_regex_files(
            &Path::new("./examples/bodyhash_allstr.txt").to_path_buf(),
            &[Path::new("./examples/bodyhash_substr_0.txt").to_path_buf()],
        )
        .unwrap();
    let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
    regex_from_decomposed
        .gen_regex_files(
            &Path::new("./examples/from_allstr.txt").to_path_buf(),
            &[Path::new("./examples/from_substr_0.txt").to_path_buf()],
        )
        .unwrap();
    let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_str(example_body_decomposed_regex_json).unwrap();
    regex_body_decomposed
        .gen_regex_files(
            &Path::new("./examples/body_allstr.txt").to_path_buf(),
            &[Path::new("./examples/body_substr_0.txt").to_path_buf()],
        )
        .unwrap();

    // 2. In this example, we generate a dummy email to construct an email verification circuit based on its configuration file ("./examples/example_email_verify.config").
    let circuit_config_path = "./examples/example_email_verify.config";
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let config_params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
    let sign_verify_config = config_params.sign_verify_config.expect("sign_verify_config is required");
    let mut rng = thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, sign_verify_config.public_key_bits).expect("failed to generate a key");
    let public_key = rsa::RsaPublicKey::from(&private_key);
    let private_key = cfdkim::DkimPrivateKey::Rsa(private_key);
    let message = concat!("From: alice@zkemail.com\r\n", "\r\n", "email was meant for @zkemailverify.",).as_bytes();
    let email = parse_mail(message).unwrap();
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let signer = SignerBuilder::new()
        .with_signed_headers(&["From"])
        .unwrap()
        .with_private_key(private_key)
        .with_selector("default")
        .with_signing_domain("zkemail.com")
        .with_logger(&logger)
        .with_header_canonicalization(cfdkim::canonicalization::Type::Relaxed)
        .with_body_canonicalization(cfdkim::canonicalization::Type::Relaxed)
        .build()
        .unwrap();
    let signature = signer.sign(&email).unwrap();
    let email_bytes = vec![signature.as_bytes(), b"\r\n", message].concat();
    let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
    let header_str = String::from_utf8(canonicalized_header.clone()).unwrap();
    println!("canonicalized header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
    let body_str = String::from_utf8(canonicalized_body.clone()).unwrap();
    println!("canonicalized body:\n{}", body_str);
    let public_key_n = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let circuit = DefaultEmailVerifyCircuit::new(email_bytes, public_key_n);
    // 3. Assert the circuit.
    let instances = circuit.instances();
    let prover = MockProver::run(config_params.degree, &circuit, instances).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // 4. Generate SRS parameters, proving and verifying keys.
    let header_config = config_params.header_config.expect("header_config is required");
    let body_config = config_params.body_config.expect("body_config is required");
    let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_config.substr_regexes, body_config.substr_regexes);
    let headerhash = Sha256::digest(&canonicalized_header).to_vec();
    let public_input = DefaultEmailVerifyPublicInput::new(headerhash.clone(), circuit.public_key_n.clone(), header_substrs, body_substrs);
    let public_input_path = "./examples/public_input.json";
    public_input.write_file(&public_input_path);
    let params_path = "./examples/test.params";
    gen_params(params_path, config_params.degree).unwrap();
    let pk_path = "./examples/test.pk";
    let vk_path = "./examples/test.vk";
    gen_app_key(params_path, circuit_config_path, pk_path, vk_path, circuit.clone()).unwrap();

    // 5. Generate a proof of the email verification circuit.
    let evm_proof_path = "./examples/test_evm.hex";
    evm_prove_app(params_path, circuit_config_path, pk_path, evm_proof_path, circuit.clone()).unwrap();

    // 6. Generate a yul bytecode and a Solidity contract of the verifier contract.
    let bytecode_path = "./examples/test_verifier.bin";
    let solidity_path = "./examples/testVerifier.sol";
    gen_evm_verifier::<DefaultEmailVerifyCircuit<Fr>>(params_path, circuit_config_path, vk_path, bytecode_path, solidity_path).unwrap();

    // 7. Verify the proof on EVM.
    let instances = DefaultEmailVerifyCircuit::<Fr>::get_instances_from_default_public_input(&public_input_path);
    evm_verify_app(circuit_config_path, bytecode_path, evm_proof_path, instances).unwrap();
    println!("The proof passed the verification!");
}
