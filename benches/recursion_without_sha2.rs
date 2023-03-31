use ark_std::{end_timer, start_timer};
use base64::engine::general_purpose;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_base::gates::flex_gate::FlexGateConfig;
use halo2_base::gates::GateInstructions;
use halo2_base::halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::poly::VerificationStrategy;
use halo2_base::halo2_proofs::poly::{commitment::Params, kzg::commitment::ParamsKZG};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error, SerdeFormat};
use halo2_base::{
    gates::range::{RangeConfig, RangeStrategy::Vertical},
    utils::PrimeField,
    Context,
};
use halo2_base::{halo2_proofs, AssignedValue, QuantumCell};
use halo2_base64::Base64Config;
use halo2_dynamic_sha256::Field;
use halo2_regex::defs::{AllstrRegexDef, SubstrRegexDef};
use halo2_regex::RegexVerifyConfig;
use halo2_rsa::{RSAConfig, RSAInstructions, RSAPubE, RSAPublicKey, RSASignature};
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
use halo2_base::SKIP_FIRST_PASS;
use halo2_zk_email::EmailVerifyConfig;
use halo2_zk_email::{impl_aggregation_email_verify, impl_email_verify_circuit};
use mailparse::parse_mail;
use num_bigint::BigUint;
use rand::thread_rng;
use rand::Rng;
use rsa::{PublicKeyParts, RsaPrivateKey};
use sha2::{self, Digest, Sha256};

#[derive(Debug, Clone)]
pub struct EmailVerifyNoSha2Config<F: Field> {
    header_regex_config: RegexVerifyConfig<F>,
    body_regex_config: RegexVerifyConfig<F>,
    base64_config: Base64Config<F>,
    rsa_config: RSAConfig<F>,
    encoded_bodyhash_instance: Column<Instance>,
    masked_str_instance: Column<Instance>,
    substr_ids_instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct EmailVerifyNoSha2Circuit<F: Field> {
    header_bytes: Vec<u8>,
    body_bytes: Vec<u8>,
    public_key: RSAPublicKey<F>,
    signature: RSASignature<F>,
    bodyhash: (usize, String),
    header_substrings: Vec<(usize, String)>,
    body_substrings: Vec<(usize, String)>,
}

impl<F: Field> CircuitExt<F> for EmailVerifyNoSha2Circuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        let max_len = Self::HEADER_MAX_BYTE_SIZE + Self::BODY_MAX_BYTE_SIZE;

        // let num_subst_defs = 1 + header_substr_defs.len() + body_substr_defs.len();
        // let mut substr_bytes_sum = body_hash_substr_def.max_length;
        // for substr_def in header_substr_defs.iter() {
        //     substr_bytes_sum += substr_def.max_length;
        // }
        // for substr_def in body_substr_defs.iter() {
        //     substr_bytes_sum += substr_def.max_length;
        // }
        vec![44, max_len, max_len]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        let max_len = Self::HEADER_MAX_BYTE_SIZE + Self::BODY_MAX_BYTE_SIZE;
        let hash_fs = self
            .bodyhash
            .1
            .as_bytes()
            .into_iter()
            .map(|byte| F::from(*byte as u64))
            .collect::<Vec<F>>();
        let header_substrings =
            vec![&[self.bodyhash.clone()][..], &self.header_substrings].concat();
        let mut expected_masked_chars = vec![F::from(0); max_len];
        let mut expected_substr_ids = vec![F::from(0); max_len];
        for (substr_idx, (start, chars)) in header_substrings.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[start + idx] = F::from(*char as u64);
                expected_substr_ids[start + idx] = F::from(substr_idx as u64 + 1);
            }
        }
        for (substr_idx, (start, chars)) in self.body_substrings.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[Self::HEADER_MAX_BYTE_SIZE + start + idx] =
                    F::from(*char as u64);
                expected_substr_ids[Self::HEADER_MAX_BYTE_SIZE + start + idx] =
                    F::from(substr_idx as u64 + 1);
            }
        }
        vec![hash_fs, expected_masked_chars, expected_substr_ids]
    }
}

impl<F: Field> Circuit<F> for EmailVerifyNoSha2Circuit<F> {
    type Config = EmailVerifyNoSha2Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            header_bytes: vec![],
            body_bytes: vec![],
            public_key: RSAPublicKey::without_witness(BigUint::from(Self::DEFAULT_E)),
            signature: RSASignature::without_witness(),
            bodyhash: (0, "".to_string()),
            header_substrings: vec![],
            body_substrings: vec![],
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let range_config = RangeConfig::configure(
            meta,
            Vertical,
            &[Self::NUM_ADVICE],
            &[Self::NUM_LOOKUP_ADVICE],
            Self::NUM_FIXED,
            Self::LOOKUP_BITS,
            0,
            Self::K as usize,
        );
        let header_regex_def = AllstrRegexDef::read_from_text("./test_data/regex_header_test1.txt");
        let body_regex_def = AllstrRegexDef::read_from_text("./test_data/regex_body_test1.txt");
        let mut header_substr_defs = vec![SubstrRegexDef::read_from_text(
            "./test_data/substr_header_test1_1.txt",
        )];
        header_substr_defs.append(
            &mut vec!["./test_data/substr_header_test1_2.txt"]
                .into_iter()
                .map(|path| SubstrRegexDef::read_from_text(path))
                .collect::<Vec<SubstrRegexDef>>(),
        );
        let body_substr_defs = vec!["./test_data/substr_body_test1_1.txt"]
            .into_iter()
            .map(|path| SubstrRegexDef::read_from_text(path))
            .collect::<Vec<SubstrRegexDef>>();
        let header_regex_config = RegexVerifyConfig::configure(
            meta,
            Self::HEADER_MAX_BYTE_SIZE,
            range_config.gate.clone(),
            header_regex_def,
            header_substr_defs,
        );
        let body_regex_config = RegexVerifyConfig::configure(
            meta,
            Self::BODY_MAX_BYTE_SIZE,
            range_config.gate.clone(),
            body_regex_def,
            body_substr_defs,
        );
        let base64_config = Base64Config::configure(meta);
        let biguint_config = halo2_rsa::BigUintConfig::construct(range_config, 64);
        let rsa_config = RSAConfig::construct(biguint_config, Self::BITS_LEN, 5);
        let encoded_bodyhash_instance = meta.instance_column();
        meta.enable_equality(encoded_bodyhash_instance);
        let masked_str_instance = meta.instance_column();
        meta.enable_equality(masked_str_instance);
        let substr_ids_instance = meta.instance_column();
        meta.enable_equality(substr_ids_instance);
        Self::Config {
            header_regex_config,
            body_regex_config,
            base64_config,
            rsa_config,
            encoded_bodyhash_instance,
            masked_str_instance,
            substr_ids_instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.header_regex_config.load(&mut layouter)?;
        config.body_regex_config.load(&mut layouter)?;
        config.base64_config.load(&mut layouter)?;
        config.rsa_config.range().load_lookup_table(&mut layouter)?;
        let mut first_pass = SKIP_FIRST_PASS;
        let mut encoded_bodyhash_cell = vec![];
        let mut masked_str_cell = vec![];
        let mut substr_id_cell = vec![];
        layouter.assign_region(
            || "zkemail",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let ctx = &mut config.rsa_config.new_context(region);
                let assigned_public_key = config
                    .rsa_config
                    .assign_public_key(ctx, self.public_key.clone())?;
                let assigned_signature = config
                    .rsa_config
                    .assign_signature(ctx, self.signature.clone())?;

                // 1. body
                let body_regex_result = config
                    .body_regex_config
                    .match_substrs(ctx, &self.body_bytes)?;
                let body_hash = Sha256::digest(&self.body_bytes).to_vec();
                let gate = config.rsa_config.gate();
                let assigned_body_hash_bytes = body_hash
                    .iter()
                    .map(|byte| gate.load_witness(ctx, Value::known(F::from(*byte as u64))))
                    .collect::<Vec<AssignedValue<F>>>();
                let mut body_hash_base64 = Vec::new();
                body_hash_base64.resize(44, 0);
                let bytes_written = general_purpose::STANDARD
                    .encode_slice(&body_hash, &mut body_hash_base64)
                    .expect("fail to convert the hash bytes into the base64 strings");
                debug_assert_eq!(bytes_written, 44);
                let base64_result = config
                    .base64_config
                    .assign_values(&mut ctx.region, &body_hash_base64)?;
                debug_assert_eq!(base64_result.decoded.len(), 32);
                for (assigned_hash, assigned_decoded) in assigned_body_hash_bytes
                    .into_iter()
                    .zip(base64_result.decoded.into_iter())
                {
                    ctx.region
                        .constrain_equal(assigned_hash.cell(), assigned_decoded.cell())?;
                }

                // 2. header
                let header_regex_result = config
                    .header_regex_config
                    .match_substrs(ctx, &self.header_bytes)?;
                let header_hash = Sha256::digest(&self.header_bytes).to_vec();
                let gate = config.rsa_config.gate();
                let mut assigned_header_hash_bytes = header_hash
                    .iter()
                    .map(|byte| gate.load_witness(ctx, Value::known(F::from(*byte as u64))))
                    .collect::<Vec<AssignedValue<F>>>();
                assigned_header_hash_bytes.reverse();
                let bytes_bits = assigned_header_hash_bytes.len() * 8;
                let limb_bits = config.rsa_config.biguint_config().limb_bits;
                let limb_bytes = limb_bits / 8;
                let mut hashed_u64s = vec![];
                let bases = (0..limb_bytes)
                    .map(|i| F::from((1u64 << (8 * i)) as u64))
                    .map(QuantumCell::Constant)
                    .collect::<Vec<QuantumCell<F>>>();
                for i in 0..(bytes_bits / limb_bits) {
                    let left = assigned_header_hash_bytes[limb_bytes * i..limb_bytes * (i + 1)]
                        .iter()
                        .map(QuantumCell::Existing)
                        .collect::<Vec<QuantumCell<F>>>();
                    let sum = gate.inner_product(ctx, left, bases.clone());
                    hashed_u64s.push(sum);
                }
                let is_sign_valid = config.rsa_config.verify_pkcs1v15_signature(
                    ctx,
                    &assigned_public_key,
                    &hashed_u64s,
                    &assigned_signature,
                )?;
                gate.assert_is_const(ctx, &is_sign_valid, F::one());

                config.rsa_config.range().finalize(ctx);
                encoded_bodyhash_cell.append(
                    &mut base64_result
                        .encoded
                        .into_iter()
                        .map(|v| v.cell())
                        .collect::<Vec<Cell>>(),
                );
                masked_str_cell.append(
                    &mut header_regex_result
                        .masked_characters
                        .into_iter()
                        .map(|v| v.cell())
                        .collect::<Vec<Cell>>(),
                );
                masked_str_cell.append(
                    &mut body_regex_result
                        .masked_characters
                        .into_iter()
                        .map(|v| v.cell())
                        .collect::<Vec<Cell>>(),
                );
                substr_id_cell.append(
                    &mut header_regex_result
                        .all_substr_ids
                        .into_iter()
                        .map(|v| v.cell())
                        .collect::<Vec<Cell>>(),
                );
                substr_id_cell.append(
                    &mut body_regex_result
                        .all_substr_ids
                        .into_iter()
                        .map(|v| v.cell())
                        .collect::<Vec<Cell>>(),
                );
                Ok(())
            },
        )?;
        for (idx, cell) in encoded_bodyhash_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.encoded_bodyhash_instance, idx)?;
        }
        for (idx, cell) in masked_str_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.masked_str_instance, idx)?;
        }
        for (idx, cell) in substr_id_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.substr_ids_instance, idx)?;
        }
        Ok(())
    }
}

impl<F: Field> EmailVerifyNoSha2Circuit<F> {
    const NUM_ADVICE: usize = 60;
    const NUM_FIXED: usize = 1;
    const NUM_LOOKUP_ADVICE: usize = 4;
    const LOOKUP_BITS: usize = 12;
    const BITS_LEN: usize = 2048;
    const DEFAULT_E: u128 = 65537;
    const HEADER_MAX_BYTE_SIZE: usize = 1024;
    const BODY_MAX_BYTE_SIZE: usize = 1024;
    const K: usize = 13;
}

const K1: usize = 22;

impl_aggregation_email_verify!(
    EmailVerifyNoSha2Config,
    EmailVerifyNoSha2Circuit,
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
    let _private_key = RsaPrivateKey::new(&mut rng, EmailVerifyNoSha2Circuit::<Fr>::BITS_LEN)
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

    let e = RSAPubE::Fix(BigUint::from(EmailVerifyNoSha2Circuit::<Fr>::DEFAULT_E));
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
    let circuit = EmailVerifyNoSha2Circuit {
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
