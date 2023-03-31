use std::collections::HashMap;

use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    AssignedValue, Context,
};
use halo2_dynamic_sha256::{Field, Sha256CompressionConfig, Sha256DynamicConfig};
use halo2_regex::{
    defs::{AllstrRegexDef, SubstrRegexDef},
    AssignedRegexResult, RegexVerifyConfig,
};

#[derive(Debug, Clone, Default)]
pub struct RegexSha2Result<'a, F: Field> {
    pub regex: AssignedRegexResult<'a, F>,
    pub hash_bytes: Vec<AssignedValue<'a, F>>,
}

#[derive(Debug, Clone)]
pub struct RegexSha2Config<F: Field> {
    pub(crate) sha256_config: Sha256DynamicConfig<F>,
    pub(crate) regex_config: RegexVerifyConfig<F>,
}

impl<F: Field> RegexSha2Config<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        max_byte_size: usize,
        num_sha2_compression_per_column: usize,
        range_config: RangeConfig<F>,
        all_regex_def: AllstrRegexDef,
        sub_regex_defs: Vec<SubstrRegexDef>,
    ) -> Self {
        let sha256_comp_configs = (0..num_sha2_compression_per_column)
            .map(|_| Sha256CompressionConfig::configure(meta))
            .collect();
        let sha256_config = Sha256DynamicConfig::construct(
            sha256_comp_configs,
            max_byte_size,
            range_config.clone(),
        );
        let regex_config = RegexVerifyConfig::configure(
            meta,
            max_byte_size,
            range_config.gate().clone(),
            all_regex_def,
            sub_regex_defs,
        );
        Self {
            sha256_config,
            regex_config,
        }
    }

    pub fn match_and_hash<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        input: &[u8],
    ) -> Result<RegexSha2Result<'a, F>, Error> {
        let max_input_size = self.sha256_config.max_byte_size;
        // 1. Let's match sub strings!
        let regex_result = self.regex_config.match_substrs(ctx, input)?;

        // Let's compute the hash!
        let assigned_hash_result = self.sha256_config.digest(ctx, input)?;
        // Assert that the same input is used in the regex circuit and the sha2 circuit.
        let gate = self.gate();
        let mut input_len_sum = gate.load_zero(ctx);
        for idx in 0..max_input_size {
            let flag = &regex_result.all_enable_flags[idx];
            let regex_input = gate.mul(
                ctx,
                QuantumCell::Existing(flag),
                QuantumCell::Existing(&regex_result.all_characters[idx]),
            );
            let sha2_input = gate.mul(
                ctx,
                QuantumCell::Existing(flag),
                QuantumCell::Existing(&assigned_hash_result.input_bytes[idx]),
            );
            gate.assert_equal(
                ctx,
                QuantumCell::Existing(&regex_input),
                QuantumCell::Existing(&sha2_input),
            );
            input_len_sum = gate.add(
                ctx,
                QuantumCell::Existing(&input_len_sum),
                QuantumCell::Existing(flag),
            );
        }
        gate.assert_equal(
            ctx,
            QuantumCell::Existing(&input_len_sum),
            QuantumCell::Existing(&assigned_hash_result.input_len),
        );
        let result = RegexSha2Result {
            regex: regex_result,
            hash_bytes: assigned_hash_result.output_bytes,
        };
        Ok(result)
    }

    pub fn range(&self) -> &RangeConfig<F> {
        self.sha256_config.range()
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        self.range().gate()
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.regex_config.load(layouter)?;
        // self.range().load_lookup_table(layouter)?;
        Ok(())
    }

    pub fn new_context<'a, 'b>(&'b self, region: Region<'a, F>) -> Context<'a, F> {
        self.sha256_config.new_context(region)
    }

    pub fn finalize(&self, ctx: &mut Context<F>) {
        self.range().finalize(ctx);
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
    struct TestRegexSha2Config<F: Field> {
        inner: RegexSha2Config<F>,
        hash_instance: Column<Instance>,
        masked_str_instance: Column<Instance>,
        substr_ids_instance: Column<Instance>,
    }

    #[derive(Debug, Clone)]
    struct TestRegexSha2<F: Field> {
        input: Vec<u8>,
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestRegexSha2<F> {
        type Config = TestRegexSha2Config<F>;
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
            let regex_def = AllstrRegexDef::read_from_text(lookup_filepath);
            let substr_def1 = SubstrRegexDef::new(
                4,
                0,
                Self::MAX_BYTE_SIZE as u64 - 1,
                HashSet::from([(29, 1), (1, 1)]),
            );
            let substr_def2 = SubstrRegexDef::new(
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
            // let state_lookup = read_regex_lookups(lookup_filepath);
            let inner = RegexSha2Config::configure(
                meta,
                Self::MAX_BYTE_SIZE,
                Self::NUM_SHA2_COMP,
                range_config,
                regex_def,
                vec![substr_def1, substr_def2],
            );
            let hash_instance = meta.instance_column();
            meta.enable_equality(hash_instance);
            let masked_str_instance = meta.instance_column();
            meta.enable_equality(masked_str_instance);
            let substr_ids_instance = meta.instance_column();
            meta.enable_equality(substr_ids_instance);
            Self::Config {
                inner,
                hash_instance,
                masked_str_instance,
                substr_ids_instance,
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
            let mut hash_bytes_cell = vec![];
            let mut masked_str_cell = vec![];
            let mut substr_id_cell = vec![];

            layouter.assign_region(
                || "regex",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let ctx = &mut config.inner.new_context(region);
                    let result = config.inner.match_and_hash(ctx, &self.input)?;
                    config.inner.finalize(ctx);
                    hash_bytes_cell.append(
                        &mut result
                            .hash_bytes
                            .into_iter()
                            .map(|byte| byte.cell())
                            .collect::<Vec<Cell>>(),
                    );
                    masked_str_cell.append(
                        &mut result
                            .regex
                            .masked_characters
                            .into_iter()
                            .map(|char| char.cell())
                            .collect::<Vec<Cell>>(),
                    );
                    substr_id_cell.append(
                        &mut result
                            .regex
                            .all_substr_ids
                            .into_iter()
                            .map(|id| id.cell())
                            .collect::<Vec<Cell>>(),
                    );
                    Ok(())
                },
            )?;
            for (idx, cell) in hash_bytes_cell.into_iter().enumerate() {
                layouter.constrain_instance(cell, config.hash_instance, idx)?;
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

    impl<F: Field> TestRegexSha2<F> {
        const MAX_BYTE_SIZE: usize = 1024;
        const NUM_SHA2_COMP: usize = 1; // ~130 columns per extra SHA2 coloumn
        const NUM_ADVICE: usize = 6;
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 1;
        const LOOKUP_BITS: usize = 12;
        const K: u32 = 13;
    }

    #[test]
    fn test_regex_sha2_valid_case1() {
        let input: Vec<u8> = "email was meant for @y.".chars().map(|c| c as u8).collect();
        let circuit = TestRegexSha2::<Fr> {
            input,
            _f: PhantomData,
        };
        let expected_output = Sha256::digest(&circuit.input);
        let hash_fs = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let mut expected_masked_chars = vec![Fr::from(0); TestRegexSha2::<Fr>::MAX_BYTE_SIZE];
        let mut expected_substr_ids = vec![Fr::from(0); TestRegexSha2::<Fr>::MAX_BYTE_SIZE];
        let correct_substrs = vec![(21, "y")];
        for (substr_idx, (start, chars)) in correct_substrs.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[start + idx] = Fr::from(*char as u64);
                expected_substr_ids[start + idx] = Fr::from(substr_idx as u64 + 1);
            }
        }
        let prover = MockProver::run(
            TestRegexSha2::<Fr>::K,
            &circuit,
            vec![hash_fs, expected_masked_chars, expected_substr_ids],
        )
        .unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_regex_sha2_valid_case2() {
        let input: Vec<u8> = "email was meant for @yjkt."
            .chars()
            .map(|c| c as u8)
            .collect();
        let circuit = TestRegexSha2::<Fr> {
            input,
            _f: PhantomData,
        };
        let expected_output = Sha256::digest(&circuit.input);
        let hash_fs = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let mut expected_masked_chars = vec![Fr::from(0); TestRegexSha2::<Fr>::MAX_BYTE_SIZE];
        let mut expected_substr_ids = vec![Fr::from(0); TestRegexSha2::<Fr>::MAX_BYTE_SIZE];
        let correct_substrs = vec![(21, "yjkt")];
        for (substr_idx, (start, chars)) in correct_substrs.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[start + idx] = Fr::from(*char as u64);
                expected_substr_ids[start + idx] = Fr::from(substr_idx as u64 + 1);
            }
        }
        let prover = MockProver::run(
            TestRegexSha2::<Fr>::K,
            &circuit,
            vec![hash_fs, expected_masked_chars, expected_substr_ids],
        )
        .unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_regex_sha2_valid_case3() {
        let input: Vec<u8> = "email was meant for @yjkt and jeiw and kirjrt and iwiw."
            .chars()
            .map(|c| c as u8)
            .collect();
        let circuit = TestRegexSha2::<Fr> {
            input,
            _f: PhantomData,
        };
        let expected_output = Sha256::digest(&circuit.input);
        let hash_fs = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let mut expected_masked_chars = vec![Fr::from(0); TestRegexSha2::<Fr>::MAX_BYTE_SIZE];
        let mut expected_substr_ids = vec![Fr::from(0); TestRegexSha2::<Fr>::MAX_BYTE_SIZE];
        let correct_substrs = vec![(21, "yjkt"), (26, "and jeiw and kirjrt and iwiw")];
        for (substr_idx, (start, chars)) in correct_substrs.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[start + idx] = Fr::from(*char as u64);
                expected_substr_ids[start + idx] = Fr::from(substr_idx as u64 + 1);
            }
        }
        let prover = MockProver::run(
            TestRegexSha2::<Fr>::K,
            &circuit,
            vec![hash_fs, expected_masked_chars, expected_substr_ids],
        )
        .unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_regex_sha2_invalid_case1() {
        let input: Vec<u8> = "email was meant for @@".chars().map(|c| c as u8).collect();
        let circuit = TestRegexSha2::<Fr> {
            input,
            _f: PhantomData,
        };
        let expected_output = Sha256::digest(&circuit.input);
        let hash_fs = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let mut expected_masked_chars = vec![Fr::from(0); TestRegexSha2::<Fr>::MAX_BYTE_SIZE];
        let mut expected_substr_ids = vec![Fr::from(0); TestRegexSha2::<Fr>::MAX_BYTE_SIZE];
        let correct_substrs = vec![(21, "@")];
        for (substr_idx, (start, chars)) in correct_substrs.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[start + idx] = Fr::from(*char as u64);
                expected_substr_ids[start + idx] = Fr::from(substr_idx as u64 + 1);
            }
        }
        let prover = MockProver::run(
            TestRegexSha2::<Fr>::K,
            &circuit,
            vec![hash_fs, expected_masked_chars, expected_substr_ids],
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
    fn test_regex_sha2_invalid_case2() {
        let input: Vec<u8> = "email was meant for @y".chars().map(|c| c as u8).collect();
        let circuit = TestRegexSha2::<Fr> {
            input,
            _f: PhantomData,
        };
        let expected_output = vec![0; 32];
        let hash_fs = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let mut expected_masked_chars = vec![Fr::from(0); TestRegexSha2::<Fr>::MAX_BYTE_SIZE];
        let mut expected_substr_ids = vec![Fr::from(0); TestRegexSha2::<Fr>::MAX_BYTE_SIZE];
        let correct_substrs = vec![(21, "y")];
        for (substr_idx, (start, chars)) in correct_substrs.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[start + idx] = Fr::from(*char as u64);
                expected_substr_ids[start + idx] = Fr::from(substr_idx as u64 + 1);
            }
        }
        let prover = MockProver::run(
            TestRegexSha2::<Fr>::K,
            &circuit,
            vec![hash_fs, expected_masked_chars, expected_substr_ids],
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
