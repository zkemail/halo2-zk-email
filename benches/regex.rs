use ark_std::{end_timer, start_timer};
use cfdkim::canonicalize_signed_email;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_base::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::{
    circuit::{Cell, Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Circuit, Column, Error, Instance},
};
use halo2_base::{
    gates::{
        flex_gate::FlexGateConfig,
        range::{RangeConfig, RangeStrategy::Vertical},
    },
    utils::PrimeField,
    Context, ContextParams, SKIP_FIRST_PASS,
};
use halo2_dynamic_sha256::Sha256DynamicConfig;
use halo2_regex::defs::RegexDefs;
use halo2_regex::vrm::DecomposedRegexConfig;
use halo2_regex::RegexVerifyConfig;
use halo2_regex::{defs::*, vrm::*, *};
use halo2_zk_email::regex_sha2::*;
use halo2_zk_email::utils::*;
use halo2_zk_email::*;
use rand::rngs::OsRng;
use rand::thread_rng;
use sha2::{self, Digest, Sha256};
use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
use snark_verifier_sdk::gen_pk;
use snark_verifier_sdk::CircuitExt;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::path::Path;

#[macro_export]
macro_rules! impl_regex_circuit {
    ($config_name:ident, $circuit_name:ident, $regex_defs:expr, $max_bytes_size:expr, $num_advice:expr, $k:expr) => {
        #[derive(Debug, Clone)]
        struct $config_name<F: PrimeField> {
            inner: RegexVerifyConfig<F>,
            instance: Column<Instance>,
        }

        #[derive(Debug, Clone)]
        struct $circuit_name<F: PrimeField> {
            input: Vec<u8>,
            _f: PhantomData<F>,
        }

        impl<F: PrimeField> Circuit<F> for $circuit_name<F> {
            type Config = $config_name<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self { input: vec![], _f: PhantomData }
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let gate = FlexGateConfig::<F>::configure(
                    meta,
                    halo2_base::gates::flex_gate::GateStrategy::Vertical,
                    &[Self::NUM_ADVICE],
                    Self::NUM_FIXED,
                    0,
                    Self::K as usize,
                );
                let regex_defs = $regex_defs;
                let inner = RegexVerifyConfig::configure(meta, Self::MAX_BYTES_SIZE, gate, regex_defs);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                Self::Config { inner, instance }
            }

            fn synthesize(&self, mut config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
                let witness_time = start_timer!(|| format!("Witness calculation"));
                config.inner.load(&mut layouter)?;
                let mut first_pass = SKIP_FIRST_PASS;
                let gate = config.inner.gate().clone();
                layouter.assign_region(
                    || "regex",
                    |region| {
                        if first_pass {
                            first_pass = false;
                            return Ok(());
                        }
                        let mut aux = Context::new(
                            region,
                            ContextParams {
                                max_rows: gate.max_rows,
                                num_context_ids: 1,
                                fixed_columns: gate.constants.clone(),
                            },
                        );
                        let ctx = &mut aux;
                        let result = config.inner.match_substrs(ctx, &self.input)?;
                        // config.sha256_config.range().finalize(ctx);
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
            const MAX_BYTES_SIZE: usize = $max_bytes_size;
            const NUM_ADVICE: usize = $num_advice;
            const NUM_FIXED: usize = 1;
            const K: u32 = $k;
        }
    };
}

impl_regex_circuit!(
    BenchRegexConfig1,
    BenchRegexCircuit1,
    vec![RegexDefs {
        allstr: AllstrRegexDef::read_from_text("./test_data/bodyhash_allstr.txt"),
        substrs: vec![SubstrRegexDef::read_from_text("./test_data/bodyhash_substr_0.txt")],
    },],
    1024,
    3,
    16
);

impl_regex_circuit!(
    BenchRegexConfig2,
    BenchRegexCircuit2,
    vec![RegexDefs {
        allstr: AllstrRegexDef::read_from_text("./test_data/from_allstr.txt"),
        substrs: vec![SubstrRegexDef::read_from_text("./test_data/from_substr_0.txt")],
    },],
    1024,
    3,
    16
);

impl_regex_circuit!(
    BenchRegexConfig3,
    BenchRegexCircuit3,
    vec![RegexDefs {
        allstr: AllstrRegexDef::read_from_text("./test_data/subject_allstr.txt"),
        substrs: vec![
            SubstrRegexDef::read_from_text("./test_data/subject_substr_0.txt"),
            SubstrRegexDef::read_from_text("./test_data/subject_substr_1.txt"),
            SubstrRegexDef::read_from_text("./test_data/subject_substr_2.txt"),
        ],
    },],
    1024,
    3,
    16
);

fn bench1(c: &mut Criterion) {
    let mut group = c.benchmark_group("bodyhash regex verification");
    group.sample_size(10);
    let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
    regex_bodyhash_decomposed
        .gen_regex_files(
            &Path::new("./examples/bodyhash_allstr.txt").to_path_buf(),
            &[Path::new("./examples/bodyhash_substr_0.txt").to_path_buf()],
        )
        .unwrap();
    let email_bytes = {
        let mut f = File::open("./test_data/test_email2.eml").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };
    let (input, _, _) = canonicalize_signed_email(&email_bytes).unwrap();
    let rng = thread_rng();
    let params = ParamsKZG::<Bn256>::setup(BenchRegexCircuit1::<Fr>::K, rng);
    {
        let circuit = BenchRegexCircuit1::<Fr> {
            input: input.clone(),
            _f: PhantomData,
        };
        // let expected_output = Sha256::digest(&circuit.input);
        // let hash_fs = expected_output.iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
        let prover = MockProver::run(BenchRegexCircuit1::<Fr>::K, &circuit, vec![vec![]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        let pk = gen_pk::<BenchRegexCircuit1<Fr>>(&params, &circuit, None);
        println!("app pk generated");
        let vk = pk.get_vk();
        let num_instance = vec![0];
        let verifier_yul = gen_evm_verifier_shplonk::<BenchRegexCircuit1<Fr>>(&params, &vk, num_instance, None);
        let proof = gen_evm_proof_shplonk(&params, &pk, circuit.clone(), vec![vec![]], &mut OsRng);
        evm_verify(verifier_yul, true, vec![vec![]], proof);
        group.bench_function("regex", |b| b.iter(|| gen_evm_proof_shplonk(&params, &pk, circuit.clone(), vec![vec![]], &mut OsRng)));
    }
}

fn bench2(c: &mut Criterion) {
    let mut group = c.benchmark_group("from regex verification");
    group.sample_size(10);
    let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
    regex_from_decomposed
        .gen_regex_files(
            &Path::new("./test_data/from_allstr.txt").to_path_buf(),
            &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
        )
        .unwrap();
    let email_bytes = {
        let mut f = File::open("./test_data/test_email2.eml").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };
    let (input, _, _) = canonicalize_signed_email(&email_bytes).unwrap();
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
    let rng = thread_rng();
    let params = ParamsKZG::<Bn256>::setup(BenchRegexCircuit1::<Fr>::K, rng);
    {
        let circuit = BenchRegexCircuit2::<Fr> {
            input: input.clone(),
            _f: PhantomData,
        };
        // let expected_output = Sha256::digest(&circuit.input);
        // let hash_fs = expected_output.iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
        let prover = MockProver::run(BenchRegexCircuit2::<Fr>::K, &circuit, vec![vec![]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        let pk = gen_pk::<BenchRegexCircuit2<Fr>>(&params, &circuit, None);
        println!("app pk generated");
        let vk = pk.get_vk();
        let num_instance = vec![0];
        let verifier_yul = gen_evm_verifier_shplonk::<BenchRegexCircuit2<Fr>>(&params, &vk, num_instance, None);
        let proof = gen_evm_proof_shplonk(&params, &pk, circuit.clone(), vec![vec![]], &mut OsRng);
        evm_verify(verifier_yul, true, vec![vec![]], proof);
        group.bench_function("regex", |b| b.iter(|| gen_evm_proof_shplonk(&params, &pk, circuit.clone(), vec![vec![]], &mut OsRng)));
    }
}

fn bench3(c: &mut Criterion) {
    let mut group = c.benchmark_group("subject regex verification");
    group.sample_size(10);
    let regex_subject_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/subject_defs.json").unwrap()).unwrap();
    regex_subject_decomposed
        .gen_regex_files(
            &Path::new("./test_data/subject_allstr.txt").to_path_buf(),
            &[
                Path::new("./test_data/subject_substr_0.txt").to_path_buf(),
                Path::new("./test_data/subject_substr_1.txt").to_path_buf(),
                Path::new("./test_data/subject_substr_2.txt").to_path_buf(),
            ],
        )
        .unwrap();
    let email_bytes = {
        let mut f = File::open("./test_data/test_email2.eml").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };
    let (input, _, _) = canonicalize_signed_email(&email_bytes).unwrap();
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
    let rng = thread_rng();
    let params = ParamsKZG::<Bn256>::setup(BenchRegexCircuit1::<Fr>::K, rng);

    {
        let circuit = BenchRegexCircuit3::<Fr> {
            input: input.clone(),
            _f: PhantomData,
        };
        // let expected_output = Sha256::digest(&circuit.input);
        // let hash_fs = expected_output.iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
        let prover = MockProver::run(BenchRegexCircuit3::<Fr>::K, &circuit, vec![vec![]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        let pk = gen_pk::<BenchRegexCircuit3<Fr>>(&params, &circuit, None);
        println!("app pk generated");
        let vk = pk.get_vk();
        let num_instance = vec![0];
        let verifier_yul = gen_evm_verifier_shplonk::<BenchRegexCircuit3<Fr>>(&params, &vk, num_instance, None);
        let proof = gen_evm_proof_shplonk(&params, &pk, circuit.clone(), vec![vec![]], &mut OsRng);
        evm_verify(verifier_yul, true, vec![vec![]], proof);
        group.bench_function("regex", |b| b.iter(|| gen_evm_proof_shplonk(&params, &pk, circuit.clone(), vec![vec![]], &mut OsRng)));
    }
}

criterion_group!(benches, bench1, bench2, bench3);
criterion_main!(benches);
