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
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use halo2_zk_email::{DefaultEmailVerifyCircuit, EmailVerifyConfig, EMAIL_VERIFY_CONFIG_ENV};
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

// impl_email_verify_circuit!(
//     Bench1EmailVerifyConfig,
//     Bench1EmailVerifyCircuit,
//     1,
//     1024,
//     "./test_data/regex_header_test1.txt",
//     "./test_data/substr_header_bench1_1.txt",
//     vec!["./test_data/substr_header_bench1_2.txt"],
//     1024,
//     "./test_data/regex_body_test1.txt",
//     vec!["./test_data/substr_body_bench1_1.txt"],
//     2048,
//     60,
//     4,
//     13
// );

fn gen_or_get_params(k: usize) -> ParamsKZG<Bn256> {
    let path = format!("params_{}.bin", k);
    match File::open(&path) {
        Ok(f) => {
            let mut reader = BufReader::new(f);
            ParamsKZG::read(&mut reader).unwrap()
        }
        Err(_) => {
            let params = ParamsKZG::<Bn256>::setup(k as u32, OsRng);
            params.write(&mut BufWriter::new(File::create(&path).unwrap())).unwrap();
            params
        }
    }
}

fn bench_email_verify1(c: &mut Criterion) {
    let mut group = c.benchmark_group("email bench1 with recursion");
    group.sample_size(10);
    set_var(EMAIL_VERIFY_CONFIG_ENV, "./configs/default_app.config");
    let config_params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
    let params = gen_or_get_params(config_params.degree as usize);
    println!("gen_params");
    let config_params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
    let mut rng = thread_rng();
    // let _private_key = RsaPrivateKey::new(&mut rng, config_params.public_key_bits)
    //     .expect("failed to generate a key");
    // let public_key = rsa::RsaPublicKey::from(&_private_key);
    // let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
    // let message = concat!(
    //     "From: alice@zkemail.com\r\n",
    //     "\r\n",
    //     "email was meant for @zkemailverify.",
    // )
    // .as_bytes();
    // let email = parse_mail(message).unwrap();
    // let logger = slog::Logger::root(slog::Discard, slog::o!());
    // let signer = SignerBuilder::new()
    //     .with_signed_headers(&["From"])
    //     .unwrap()
    //     .with_private_key(private_key)
    //     .with_selector("default")
    //     .with_signing_domain("zkemail.com")
    //     .with_logger(&logger)
    //     .with_header_canonicalization(cfdkim::canonicalization::Type::Relaxed)
    //     .with_body_canonicalization(cfdkim::canonicalization::Type::Relaxed)
    //     .build()
    //     .unwrap();
    // let signature = signer.sign(&email).unwrap();
    // println!("signature {}", signature);
    // let new_msg = vec![signature.as_bytes(), b"\r\n", message].concat();
    let email_bytes = {
        let mut f = File::open("./test_data/test_email1.eml").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let runtime = Runtime::new().unwrap();
    let public_key = runtime.block_on(async { resolve_public_key(&logger, &email_bytes).await }).unwrap();
    let public_key = match public_key {
        cfdkim::DkimPublicKey::Rsa(pk) => pk,
        _ => panic!("not supportted public key type."),
    };
    let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
    println!("header {}", String::from_utf8(canonicalized_header.clone()).unwrap());
    let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
    let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
    // let hash = Sha256::digest(&canonicalized_body);
    // let mut expected_output = Vec::new();
    // expected_output.resize(44, 0);
    // BASE64_STANDARD
    //     .encode_slice(&hash, &mut expected_output)
    //     .unwrap();
    // let bodyhash_regex = Regex::new(r"(?<=bh=)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|\+|/|=)+(?=;)").unwrap();
    // let canonicalized_header_str = String::from_utf8(canonicalized_header.clone()).unwrap();
    // let bodyhash_match = bodyhash_regex
    //     .find(&canonicalized_header_str)
    //     .unwrap()
    //     .unwrap();
    // let bodyhash = (
    //     bodyhash_match.start(),
    //     String::from_utf8(expected_output).unwrap(),
    // );
    // let header_substr1_regex = Regex::new(r"(?<=from:)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|.)+(?=\r)").unwrap();
    // let header_substr1_match = header_substr1_regex
    //     .find(&canonicalized_header_str)
    //     .unwrap()
    //     .unwrap();
    // let body_substr1_regex = Regex::new(r"(?<=email was meant for @)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+(?=.)").unwrap();
    // let canonicalized_body_str = String::from_utf8(canonicalized_body.clone()).unwrap();
    // let body_substr1_match = body_substr1_regex
    //     .find(&canonicalized_body_str)
    //     .unwrap()
    //     .unwrap();
    // let header_substrings = vec![(
    //     header_substr1_match.start(),
    //     header_substr1_match.as_str().to_string(),
    // )];
    // let body_substrings = vec![(
    //     body_substr1_match.start(),
    //     body_substr1_match.as_str().to_string(),
    // )];
    let circuit = DefaultEmailVerifyCircuit {
        header_bytes: canonicalized_header,
        body_bytes: canonicalized_body,
        public_key,
        signature,
    };
    MockProver::run(params.k(), &circuit, circuit.instances()).unwrap().assert_satisfied();
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
    group.bench_function("bench 1", |b| {
        b.iter(|| gen_proof_shplonk(&params, &pk, circuit.clone(), circuit.instances(), &mut OsRng, None))
    });
    group.finish();
}

criterion_group!(benches, bench_email_verify1,);
criterion_main!(benches);
