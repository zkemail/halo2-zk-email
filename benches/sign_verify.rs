use ark_std::{end_timer, start_timer};
use cfdkim::{canonicalize_signed_email, resolve_public_key};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_base::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::{
    circuit::{Cell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Circuit, Column, Error, Instance},
};
use halo2_base::{
    gates::{
        range::{RangeConfig, RangeStrategy::Vertical},
        GateInstructions, RangeInstructions,
    },
    utils::PrimeField,
    AssignedValue, SKIP_FIRST_PASS,
};
use halo2_dynamic_sha256::Sha256DynamicConfig;
use halo2_regex::defs::RegexDefs;
use halo2_regex::vrm::DecomposedRegexConfig;
use halo2_regex::{defs::*, vrm::*, *};
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use halo2_zk_email::regex_sha2::*;
use halo2_zk_email::sign_verify::SignVerifyConfig;
use halo2_zk_email::utils::*;
use halo2_zk_email::*;
use num_bigint::BigUint;
use rand::rngs::OsRng;
use rand::thread_rng;
use rsa::PublicKeyParts;
use rsa::RsaPublicKey;
use sha2::{self, Digest, Sha256};
use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
use snark_verifier_sdk::gen_pk;
use snark_verifier_sdk::CircuitExt;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::path::Path;
use tokio::runtime::Runtime;

#[macro_export]
macro_rules! impl_sign_verify_circuit {
    ($config_name:ident, $circuit_name:ident, $num_advice:expr, $num_lookup_advice:expr, $lookup_bits:expr, $k:expr) => {
        #[derive(Debug, Clone)]
        struct $config_name<F: PrimeField> {
            inner: SignVerifyConfig<F>,
            instance: Column<Instance>,
        }

        #[derive(Debug, Clone)]
        struct $circuit_name<F: PrimeField> {
            input: Vec<u8>,
            public_key: RSAPublicKey<F>,
            signature: RSASignature<F>,
        }

        impl<F: PrimeField> Circuit<F> for $circuit_name<F> {
            type Config = $config_name<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self {
                    input: vec![],
                    public_key: self.public_key.clone(),
                    signature: self.signature.clone(),
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
                // let sha256_config = Sha256DynamicConfig::configure(meta, vec![Self::MAX_BYTES_SIZE], range_config.clone(), $num_bits_lookup, $num_advice_columns, false);
                // let inner = RegexSha2Config::configure(meta, Self::MAX_BYTES_SIZE, Self::SKIP_PREFIX_BYTES_SIZE, range_config, regex_defs);
                let inner = SignVerifyConfig::configure(range_config, 2048);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                // let masked_str_instance = meta.instance_column();
                // meta.enable_equality(masked_str_instance);
                // let substr_ids_instance = meta.instance_column();
                // meta.enable_equality(substr_ids_instance);
                Self::Config { inner, instance }
            }

            fn synthesize(&self, mut config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
                let witness_time = start_timer!(|| format!("Witness calculation"));
                // config.inner.load(&mut layouter)?;
                let range = config.inner.rsa_config.range().clone();
                range.load_lookup_table(&mut layouter)?;
                let mut first_pass = SKIP_FIRST_PASS;
                // let mut hash_bytes_cell = vec![];
                // let mut masked_str_cell = vec![];
                // let mut substr_id_cell = vec![];

                layouter.assign_region(
                    || "regex",
                    |region| {
                        if first_pass {
                            first_pass = false;
                            return Ok(());
                        }
                        let ctx = &mut config.inner.rsa_config.new_context(region);
                        let hash_value = Sha256::digest(&self.input).to_vec();
                        let assigned_hash = hash_value
                            .iter()
                            .map(|byte| range.gate().load_witness(ctx, Value::known(F::from(*byte as u64))))
                            .collect::<Vec<AssignedValue<F>>>();
                        let (assigned_public_key, _) = config.inner.verify_signature(ctx, &assigned_hash, self.public_key.clone(), self.signature.clone())?;
                        // let result = config.inner.match_and_hash(ctx, &mut config.sha256_config, &self.input)?;
                        range.finalize(ctx);
                        // hash_bytes_cell.append(&mut result.hash_bytes.into_iter().map(|byte| byte.cell()).collect::<Vec<Cell>>());
                        // masked_str_cell.append(&mut result.regex.masked_characters.into_iter().map(|character| character.cell()).collect::<Vec<Cell>>());
                        // substr_id_cell.append(&mut result.regex.all_substr_ids.into_iter().map(|id| id.cell()).collect::<Vec<Cell>>());
                        Ok(())
                    },
                )?;
                end_timer!(witness_time);
                // for (idx, cell) in hash_bytes_cell.into_iter().enumerate() {
                //     layouter.constrain_instance(cell, config.hash_instance, idx)?;
                // }
                // for (idx, cell) in masked_str_cell.into_iter().enumerate() {
                //     layouter.constrain_instance(cell, config.masked_str_instance, idx)?;
                // }
                // for (idx, cell) in substr_id_cell.into_iter().enumerate() {
                //     layouter.constrain_instance(cell, config.substr_ids_instance, idx)?;
                // }

                Ok(())
            }
        }

        impl<F: PrimeField> CircuitExt<F> for $circuit_name<F> {
            fn num_instance(&self) -> Vec<usize> {
                vec![0]
            }

            fn instances(&self) -> Vec<Vec<F>> {
                vec![vec![]]
            }
        }

        impl<F: PrimeField> $circuit_name<F> {
            const NUM_ADVICE: usize = $num_advice;
            const NUM_FIXED: usize = 1;
            const NUM_LOOKUP_ADVICE: usize = $num_lookup_advice;
            const LOOKUP_BITS: usize = $lookup_bits;
            const K: u32 = $k;
        }
    };
}

impl_sign_verify_circuit!(BenchSignVerifyConfig1, BenchSignVerifyCircuit1, 6, 1, 15, 16);

fn bench_sign_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign verify 2048 bytes pk");
    group.sample_size(10);
    let email_bytes = {
        let mut f = File::open("./test_data/test_email2.eml").unwrap();
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
    let (canonicalized_header, _, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
    // let input_str = String::from_utf8(input.clone()).unwrap();
    // let mut expected_masked_chars = vec![Fr::from(0); BenchRegexSha2Circuit1::<Fr>::MAX_BYTES_SIZE];
    // let mut expected_substr_ids = vec![Fr::from(0); BenchRegexSha2Circuit1::<Fr>::MAX_BYTES_SIZE];
    // let correct_substrs = vec![
    //     get_substr(&input_str, &[r"(?<=from:).*@.*(?=\r)".to_string()]).unwrap(),
    //     get_substr(&input_str, &[r"(?<=to:).*@.*(?=\r)".to_string()]).unwrap(),
    //     get_substr(&input_str, &[r"(?<=subject:).*(?=\r)".to_string()]).unwrap(),
    // ];
    // for (substr_idx, (start, chars)) in correct_substrs.iter().enumerate() {
    //     for (idx, char) in chars.as_bytes().iter().enumerate() {
    //         expected_masked_chars[start + idx] = Fr::from(*char as u64);
    //         expected_substr_ids[start + idx] = Fr::from(substr_idx as u64 + 1);
    //     }
    // }
    let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
    let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
    let circuit = BenchSignVerifyCircuit1::<Fr> {
        input: canonicalized_header,
        public_key,
        signature,
    };
    // let expected_output = Sha256::digest(&circuit.input);
    // let hash_fs = expected_output.iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
    let prover = MockProver::run(BenchSignVerifyCircuit1::<Fr>::K, &circuit, vec![vec![]]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
    let rng = thread_rng();
    let params = ParamsKZG::<Bn256>::setup(BenchSignVerifyCircuit1::<Fr>::K, rng);
    let pk = gen_pk::<BenchSignVerifyCircuit1<Fr>>(&params, &circuit, None);
    println!("app pk generated");
    let vk = pk.get_vk();
    let num_instance = vec![0];
    let verifier_yul = gen_evm_verifier_shplonk::<BenchSignVerifyCircuit1<Fr>>(&params, &vk, num_instance, None);
    let proof = gen_evm_proof_shplonk(&params, &pk, circuit.clone(), vec![vec![]], &mut OsRng);
    evm_verify(verifier_yul, true, vec![vec![]], proof);
    group.bench_function("sign_verify", |b| b.iter(|| gen_evm_proof_shplonk(&params, &pk, circuit.clone(), vec![vec![]], &mut OsRng)));
}

criterion_group!(benches, bench_sign_verify);
criterion_main!(benches);
