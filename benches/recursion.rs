use ark_std::{end_timer, start_timer};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_base::halo2_proofs;
use halo2_base::halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::poly::{commitment::Params, kzg::commitment::ParamsKZG};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error, SerdeFormat};
use halo2_base::{gates::range::RangeConfig, utils::PrimeField, Context};
use halo2_dynamic_sha256::Field;
use halo2_regex::defs::{AllstrRegexDef, SubstrRegexDef};
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use rand::rngs::OsRng;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_proof_shplonk, gen_snark_shplonk},
    CircuitExt, Snark,
};
use std::{
    fs::File,
    io::{prelude::*, BufReader, BufWriter},
    path::Path,
};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use cfdkim::*;
use fancy_regex::Regex;
use halo2_base::halo2_proofs::{
    circuit::{floor_planner::V1, Cell, Value},
    dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
    plonk::{Any, Column, Instance, ProvingKey, VerifyingKey},
};
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_zk_email::EmailVerifyConfig;
use halo2_zk_email::{impl_aggregation_email_verify, impl_email_verify_circuit};
use mailparse::parse_mail;
use num_bigint::BigUint;
use rand::thread_rng;
use rand::Rng;
use rsa::{PublicKeyParts, RsaPrivateKey};
use sha2::{self, Digest, Sha256};

impl_email_verify_circuit!(
    Bench1EmailVerifyConfig,
    Bench1EmailVerifyCircuit,
    1,
    1024,
    "./test_data/regex_header_test1.txt",
    "./test_data/substr_header_bench1_1.txt",
    vec!["./test_data/substr_header_bench1_2.txt"],
    1024,
    "./test_data/regex_body_test1.txt",
    vec!["./test_data/substr_body_bench1_1.txt"],
    2048,
    60,
    4,
    13
);

const K1: usize = 22;

impl_aggregation_email_verify!(
    Bench1EmailVerifyConfig,
    Bench1EmailVerifyCircuit,
    gen_bench1_email_pk,
    gen_bench1_email_snark,
    gen_bench1_agg_pk,
    gen_bench1_agg_proof,
    K1
);

fn gen_or_get_params(k: usize) -> ParamsKZG<Bn256> {
    let path = format!("params_{}.bin", k);
    match File::open(&path) {
        Ok(f) => {
            let mut reader = BufReader::new(f);
            ParamsKZG::read(&mut reader).unwrap()
        }
        Err(_) => {
            let params = ParamsKZG::<Bn256>::setup(k as u32, OsRng);
            params
                .write(&mut BufWriter::new(File::create(&path).unwrap()))
                .unwrap();
            params
        }
    }
}

fn gen_or_get_pk1(agg_params: &ParamsKZG<Bn256>, snarks: &[Snark]) -> ProvingKey<G1Affine> {
    let path = "proving_key_1.pk";
    match File::open(&path) {
        Ok(f) => {
            let mut reader = BufReader::new(f);
            ProvingKey::<G1Affine>::read::<_, AggregationCircuit>(
                &mut reader,
                SerdeFormat::RawBytes,
            )
            .unwrap()
        }
        Err(_) => {
            let agg_pk = gen_bench1_agg_pk(&agg_params, snarks.to_vec(), &mut OsRng);
            agg_pk
                .write(
                    &mut BufWriter::new(File::create(&path).unwrap()),
                    SerdeFormat::RawBytes,
                )
                .unwrap();
            agg_pk
        }
    }
}

fn bench_email_verify_recursion1(c: &mut Criterion) {
    let mut group = c.benchmark_group("email bench1 with recursion");
    group.sample_size(10);
    let agg_params = gen_or_get_params(K1);
    println!("gen_params");
    let app_params = {
        let mut params = agg_params.clone();
        params.downsize(15);
        params
    };
    let mut rng = thread_rng();
    let _private_key = RsaPrivateKey::new(&mut rng, Bench1EmailVerifyCircuit::<Fr>::BITS_LEN)
        .expect("failed to generate a key");
    let public_key = rsa::RsaPublicKey::from(&_private_key);
    let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
    let message = concat!(
        "From: alice@zkemail.com\r\n",
        "\r\n",
        "email was meant for @zkemailverify.",
    )
    .as_bytes();
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
    println!("signature {}", signature);
    let new_msg = vec![signature.as_bytes(), b"\r\n", message].concat();
    let (canonicalized_header, canonicalized_body, signature_bytes) =
        canonicalize_signed_email(&new_msg).unwrap();

    let e = RSAPubE::Fix(BigUint::from(Bench1EmailVerifyCircuit::<Fr>::DEFAULT_E));
    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
    let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
    let hash = Sha256::digest(&canonicalized_body);
    let mut expected_output = Vec::new();
    expected_output.resize(44, 0);
    BASE64_STANDARD
        .encode_slice(&hash, &mut expected_output)
        .unwrap();
    // let substrings = vec![
    //     String::from_utf8(expected_output).unwrap(),
    //     "alice@zkemail.com".to_string(),
    //     "zkemailverify".to_string(),
    // ];
    let bodyhash_regex = Regex::new(r"(?<=bh=)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|\+|/|=)+(?=;)").unwrap();
    let canonicalized_header_str = String::from_utf8(canonicalized_header.clone()).unwrap();
    let bodyhash_match = bodyhash_regex
        .find(&canonicalized_header_str)
        .unwrap()
        .unwrap();
    let bodyhash = (
        bodyhash_match.start(),
        String::from_utf8(expected_output).unwrap(),
    );
    let header_substr1_regex = Regex::new(r"(?<=from:)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|.)+(?=\r)").unwrap();
    let header_substr1_match = header_substr1_regex
        .find(&canonicalized_header_str)
        .unwrap()
        .unwrap();
    let body_substr1_regex = Regex::new(r"(?<=email was meant for @)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+(?=.)").unwrap();
    let canonicalized_body_str = String::from_utf8(canonicalized_body.clone()).unwrap();
    let body_substr1_match = body_substr1_regex
        .find(&canonicalized_body_str)
        .unwrap()
        .unwrap();
    let header_substrings = vec![(
        header_substr1_match.start(),
        header_substr1_match.as_str().to_string(),
    )];
    let body_substrings = vec![(
        body_substr1_match.start(),
        body_substr1_match.as_str().to_string(),
    )];
    let circuit = Bench1EmailVerifyCircuit {
        header_bytes: canonicalized_header,
        body_bytes: canonicalized_body,
        public_key,
        signature,
        bodyhash,
        header_substrings,
        body_substrings,
    };
    let mock = start_timer!(|| "app pk generation");
    let app_pk = gen_bench1_email_pk(&app_params, circuit.clone());
    end_timer!(mock);
    println!("application proving key is generated.");
    let mock = start_timer!(|| "app snarks generation");
    let snarks = [(); 2].map(|_| gen_bench1_email_snark(&app_params, circuit.clone(), &app_pk));
    end_timer!(mock);
    println!("application snarks are generated.");
    // let agg_pk = gen_bench1_agg_pk(&agg_params, snarks.to_vec(), &mut OsRng);
    let mock = start_timer!(|| "aggregation pk generation");
    let agg_pk = gen_or_get_pk1(&agg_params, &snarks);
    end_timer!(mock);
    println!("aggregation proving key is generated.");
    group.bench_function("bench 1", |b| {
        b.iter(|| gen_bench1_agg_proof(&agg_params, &agg_pk, snarks.to_vec(), &mut OsRng))
    });
    group.finish();
}

criterion_group!(benches, bench_email_verify_recursion1,);
criterion_main!(benches);
