use std::collections::HashMap;

use crate::regex_sha2::RegexSha2Config;
use base64::{engine::general_purpose, Engine as _};
use halo2_base::halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region},
    plonk::{ConstraintSystem, Error},
};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, RangeInstructions},
    Context,
};
use halo2_base64::Base64Config;
use halo2_dynamic_sha256::Field;
use halo2_regex::{AssignedSubstrsResult, RegexDef, SubstrDef};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct RegexSha2Base64Result<'a, F: Field> {
    pub substrs: AssignedSubstrsResult<'a, F>,
    pub encoded_hash: Vec<AssignedCell<F, F>>,
}

#[derive(Debug, Clone)]
pub struct RegexSha2Base64Config<F: Field> {
    pub(crate) regex_sha2: RegexSha2Config<F>,
    pub(crate) base64_config: Base64Config<F>,
}

impl<F: Field> RegexSha2Base64Config<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        max_byte_size: usize,
        num_sha2_compression_per_column: usize,
        range_config: RangeConfig<F>,
        regex_def: RegexDef,
        substr_defs: Vec<SubstrDef>,
    ) -> Self {
        let regex_sha2 = RegexSha2Config::configure(
            meta,
            max_byte_size,
            num_sha2_compression_per_column,
            range_config,
            regex_def,
            substr_defs,
        );
        let base64_config = Base64Config::configure(meta);
        Self {
            regex_sha2,
            base64_config,
        }
    }

    pub fn match_hash_and_base64<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        input: &[u8],
    ) -> Result<RegexSha2Base64Result<'a, F>, Error> {
        let regex_sha2_result = self.regex_sha2.match_and_hash(ctx, input)?;

        let actual_hash = Sha256::digest(input).to_vec();
        debug_assert_eq!(actual_hash.len(), 32);
        let mut hash_base64 = Vec::new();
        hash_base64.resize(44, 0);
        let bytes_written = general_purpose::STANDARD
            .encode_slice(&actual_hash, &mut hash_base64)
            .expect("fail to convert the hash bytes into the base64 strings");
        debug_assert_eq!(bytes_written, 44);
        // println!(
        //     "hash_base64 {}",
        //     String::from_utf8(hash_base64.to_vec()).unwrap()
        // );
        let base64_result = self
            .base64_config
            .assign_values(&mut ctx.region, &hash_base64)?;
        debug_assert_eq!(base64_result.decoded.len(), 32);
        for (assigned_hash, assigned_decoded) in regex_sha2_result
            .hash_bytes
            .into_iter()
            .zip(base64_result.decoded.into_iter())
        {
            ctx.region
                .constrain_equal(assigned_hash.cell(), assigned_decoded.cell())?;
        }
        let result = RegexSha2Base64Result {
            substrs: regex_sha2_result.substrs,
            encoded_hash: base64_result.encoded,
        };
        Ok(result)
    }

    pub fn range(&self) -> &RangeConfig<F> {
        self.regex_sha2.range()
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        self.range().gate()
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.regex_sha2.load(layouter)?;
        self.base64_config.load(layouter)?;
        Ok(())
    }

    pub fn new_context<'a, 'b>(&'b self, region: Region<'a, F>) -> Context<'a, F> {
        self.regex_sha2.new_context(region)
    }

    pub fn finalize(&self, ctx: &mut Context<F>) {
        self.regex_sha2.finalize(ctx);
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use std::marker::PhantomData;

    use super::*;

    use halo2_base::halo2_proofs::{
        circuit::{floor_planner::V1, Cell, SimpleFloorPlanner},
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Fr, G1},
        plonk::{Any, Circuit, Column, Instance},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
    use sha2::{self, Digest, Sha256};

    #[derive(Debug, Clone)]
    struct TestRegexSha2Base64Config<F: Field> {
        inner: RegexSha2Base64Config<F>,
        hash_instance: Column<Instance>,
        substr_len_instance: Column<Instance>,
    }

    #[derive(Debug, Clone)]
    struct TestRegexSha2Base64<F: Field> {
        input: Vec<u8>,
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestRegexSha2Base64<F> {
        type Config = TestRegexSha2Base64Config<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                input: vec![],
                _f: PhantomData,
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
            let lookup_filepath = "./test_data/regex_test_lookup.txt";
            let regex_def = RegexDef::read_from_text(lookup_filepath);
            let substr_def1 = SubstrDef::new(
                4,
                0,
                Self::MAX_BYTE_SIZE as u64 - 1,
                HashSet::from([(29, 1), (1, 1)]),
            );
            let substr_def2 = SubstrDef::new(
                11,
                0,
                Self::MAX_BYTE_SIZE as u64 - 1,
                HashSet::from([
                    (4, 8),
                    (8, 9),
                    (9, 10),
                    (10, 11),
                    (11, 12),
                    (12, 4),
                    (12, 12),
                ]),
            );
            let inner = RegexSha2Base64Config::configure(
                meta,
                Self::MAX_BYTE_SIZE,
                Self::NUM_SHA2_COMP,
                range_config,
                regex_def,
                vec![substr_def1, substr_def2],
            );
            let hash_instance = meta.instance_column();
            meta.enable_equality(hash_instance);
            let substr_len_instance = meta.instance_column();
            meta.enable_equality(substr_len_instance);
            Self::Config {
                inner,
                hash_instance,
                substr_len_instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.inner.load(&mut layouter)?;
            config.inner.range().load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            let mut hash_bytes_cell = None;
            let mut len_cells = Vec::new();
            layouter.assign_region(
                || "regex",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let ctx = &mut config.inner.new_context(region);
                    let result = config.inner.match_hash_and_base64(ctx, &self.input)?;
                    config.inner.finalize(ctx);
                    hash_bytes_cell = Some(
                        result
                            .encoded_hash
                            .into_iter()
                            .map(|byte| byte.cell())
                            .collect::<Vec<Cell>>(),
                    );
                    len_cells.append(
                        &mut result
                            .substrs
                            .substrs_length
                            .into_iter()
                            .map(|val| val.cell())
                            .collect(),
                    );
                    Ok(())
                },
            )?;
            for (idx, cell) in hash_bytes_cell.unwrap().into_iter().enumerate() {
                layouter.constrain_instance(cell, config.hash_instance, idx)?;
            }
            for (idx, cell) in len_cells.into_iter().enumerate() {
                layouter.constrain_instance(cell, config.substr_len_instance, idx)?;
            }
            Ok(())
        }
    }

    impl<F: Field> TestRegexSha2Base64<F> {
        const MAX_BYTE_SIZE: usize = 1024;
        const NUM_SHA2_COMP: usize = 2;
        const NUM_ADVICE: usize = 154;
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 4;
        const LOOKUP_BITS: usize = 12;
        const K: u32 = 13;
    }

    #[test]
    fn test_regex_sha2_base64_valid_case1() {
        let input: Vec<u8> = "email was meant for @y.".chars().map(|c| c as u8).collect();
        let circuit = TestRegexSha2Base64::<Fr> {
            input,
            _f: PhantomData,
        };
        let hash = Sha256::digest(&circuit.input);
        let mut expected_output = Vec::new();
        expected_output.resize(44, 0);
        general_purpose::STANDARD
            .encode_slice(&hash, &mut expected_output)
            .unwrap();
        let hash_fs = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let len_f1 = Fr::from(1);
        let len_f2 = Fr::from(0);
        let prover = MockProver::run(
            TestRegexSha2Base64::<Fr>::K,
            &circuit,
            vec![hash_fs, vec![len_f1, len_f2]],
        )
        .unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_regex_sha2_base64_valid_case2() {
        let input: Vec<u8> = "email was meant for @yjkt."
            .chars()
            .map(|c| c as u8)
            .collect();
        let circuit = TestRegexSha2Base64::<Fr> {
            input,
            _f: PhantomData,
        };
        let hash = Sha256::digest(&circuit.input);
        let mut expected_output = Vec::new();
        expected_output.resize(44, 0);
        general_purpose::STANDARD
            .encode_slice(&hash, &mut expected_output)
            .unwrap();
        let hash_fs = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let len_f1 = Fr::from(4);
        let len_f2 = Fr::from(0);
        let prover = MockProver::run(
            TestRegexSha2Base64::<Fr>::K,
            &circuit,
            vec![hash_fs, vec![len_f1, len_f2]],
        )
        .unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_regex_sha2_base64_valid_case3() {
        let input: Vec<u8> = "email was meant for @yjkt and jeiw and kirjrt and iwiw."
            .chars()
            .map(|c| c as u8)
            .collect();
        let circuit = TestRegexSha2Base64::<Fr> {
            input,
            _f: PhantomData,
        };
        let hash = Sha256::digest(&circuit.input);
        let mut expected_output = Vec::new();
        expected_output.resize(44, 0);
        general_purpose::STANDARD
            .encode_slice(&hash, &mut expected_output)
            .unwrap();
        let hash_fs = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let len_f1 = Fr::from(4);
        let len_f2 = Fr::from(28);
        let prover = MockProver::run(
            TestRegexSha2Base64::<Fr>::K,
            &circuit,
            vec![hash_fs, vec![len_f1, len_f2]],
        )
        .unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_regex_sha2_base64_invalid_case1() {
        let input: Vec<u8> = "email was meant for @@.".chars().map(|c| c as u8).collect();
        let circuit = TestRegexSha2Base64::<Fr> {
            input,
            _f: PhantomData,
        };
        let hash = Sha256::digest(&circuit.input);
        let mut expected_output = Vec::new();
        expected_output.resize(44, 0);
        general_purpose::STANDARD
            .encode_slice(&hash, &mut expected_output)
            .unwrap();
        let hash_fs = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let len_f1 = Fr::from(0);
        let len_f2 = Fr::from(0);
        let prover = MockProver::run(
            TestRegexSha2Base64::<Fr>::K,
            &circuit,
            vec![hash_fs, vec![len_f1, len_f2]],
        )
        .unwrap();
        match prover.verify() {
            Err(_) => {
                println!("Error successfully achieved!");
            }
            _ => assert!(false, "Should be error."),
        }
    }

    #[test]
    fn test_regex_sha2_base64_invalid_case2() {
        let input: Vec<u8> = "email was meant for @y".chars().map(|c| c as u8).collect();
        let circuit = TestRegexSha2Base64::<Fr> {
            input,
            _f: PhantomData,
        };
        let hash = [0; 32];
        let mut expected_output = Vec::new();
        expected_output.resize(44, 0);
        general_purpose::STANDARD
            .encode_slice(&hash, &mut expected_output)
            .unwrap();
        let hash_fs = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let len_f1 = Fr::from(0);
        let len_f2 = Fr::from(0);
        let prover = MockProver::run(
            TestRegexSha2Base64::<Fr>::K,
            &circuit,
            vec![hash_fs, vec![len_f1, len_f2]],
        )
        .unwrap();
        match prover.verify() {
            Err(_) => {
                println!("Error successfully achieved!");
            }
            _ => assert!(false, "Should be error."),
        }
    }
}
