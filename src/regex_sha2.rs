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
use halo2_regex::{AssignedSubstrsResult, RegexCheckConfig, SubstrDef, SubstrMatchConfig};

#[derive(Debug, Clone, Default)]
pub struct RegexSha2Result<'a, F: Field> {
    pub substrs: AssignedSubstrsResult<'a, F>,
    pub hash_bytes: Vec<AssignedValue<'a, F>>,
}

#[derive(Debug, Clone)]
pub struct RegexSha2Config<F: Field> {
    pub(crate) sha256_config: Sha256DynamicConfig<F>,
    pub(crate) substr_match_config: SubstrMatchConfig<F>,
}

impl<F: Field> RegexSha2Config<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        max_byte_size: usize,
        num_sha2_compression_per_column: usize,
        range_config: RangeConfig<F>,
        state_lookup: HashMap<(u8, u64), u64>,
        accepted_state_vals: &[u64],
        substr_defs: Vec<SubstrDef>,
    ) -> Self {
        let sha256_comp_configs = (0..num_sha2_compression_per_column)
            .map(|_| Sha256CompressionConfig::configure(meta))
            .collect();
        let sha256_config = Sha256DynamicConfig::construct(
            sha256_comp_configs,
            max_byte_size,
            range_config.clone(),
        );
        let regex_config =
            RegexCheckConfig::configure(meta, state_lookup, accepted_state_vals, max_byte_size);
        let substr_match_config =
            SubstrMatchConfig::construct(regex_config, range_config.gate().clone(), substr_defs);
        Self {
            sha256_config,
            substr_match_config,
        }
    }

    pub fn match_and_hash<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        input: &[u8],
    ) -> Result<RegexSha2Result<'a, F>, Error> {
        let max_input_size = self.sha256_config.max_byte_size;
        // 1. Let's match sub strings!
        let regex_result = self.substr_match_config.match_substrs(ctx, input)?;

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
            substrs: regex_result,
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
        self.substr_match_config.load(layouter)?;
        self.range().load_lookup_table(layouter)?;
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
    use std::marker::PhantomData;

    pub use super::*;

    use halo2_base::halo2_proofs::{
        circuit::{floor_planner::V1, Cell, SimpleFloorPlanner},
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Fr, G1},
        plonk::{Any, Circuit, Column, Instance},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
    use halo2_regex::read_regex_lookups;
    use sha2::{self, Digest, Sha256};

    #[derive(Debug, Clone)]
    struct TestRegexSha2Config<F: Field> {
        inner: RegexSha2Config<F>,
        hash_instance: Column<Instance>,
        substr_len_instance: Column<Instance>,
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
            let lookup_filepath = "./test_regexes/regex_test_lookup.txt";
            let state_lookup = read_regex_lookups(lookup_filepath);
            let substr_def = SubstrDef::new(4, 21, Self::MAX_BYTE_SIZE as u64 - 4, 22);
            let inner = RegexSha2Config::configure(
                meta,
                Self::MAX_BYTE_SIZE,
                Self::NUM_SHA2_COMP,
                range_config,
                state_lookup,
                &[Self::ACCEPTED_STATE],
                vec![substr_def],
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
            let mut first_pass = SKIP_FIRST_PASS;
            let mut hash_bytes_cell = None;
            let mut len_cell = None;
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
                    hash_bytes_cell = Some(
                        result
                            .hash_bytes
                            .into_iter()
                            .map(|byte| byte.cell())
                            .collect::<Vec<Cell>>(),
                    );
                    len_cell = Some(result.substrs.substrs_length[0].cell());
                    Ok(())
                },
            )?;
            for (idx, cell) in hash_bytes_cell.unwrap().into_iter().enumerate() {
                layouter.constrain_instance(cell, config.hash_instance, idx)?;
            }
            layouter.constrain_instance(len_cell.unwrap(), config.substr_len_instance, 0)?;
            Ok(())
        }
    }

    impl<F: Field> TestRegexSha2<F> {
        const MAX_BYTE_SIZE: usize = 1024;
        const NUM_SHA2_COMP: usize = 2;
        const NUM_ADVICE: usize = 50;
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 4;
        const LOOKUP_BITS: usize = 12;
        const K: u32 = 13;
        const ACCEPTED_STATE: u64 = 23;
    }

    #[test]
    fn test_regex_sha2_valid_case1() {
        let input: Vec<u8> = "email was meant for @y".chars().map(|c| c as u8).collect();
        let circuit = TestRegexSha2::<Fr> {
            input,
            _f: PhantomData,
        };
        let expected_output = Sha256::digest(&circuit.input);
        let hash_fs = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let len_f = Fr::from(1);
        let prover =
            MockProver::run(TestRegexSha2::<Fr>::K, &circuit, vec![hash_fs, vec![len_f]]).unwrap();
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
        let len_f = Fr::from(1);
        let prover =
            MockProver::run(TestRegexSha2::<Fr>::K, &circuit, vec![hash_fs, vec![len_f]]).unwrap();
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
        let len_f = Fr::from(1);
        let prover =
            MockProver::run(TestRegexSha2::<Fr>::K, &circuit, vec![hash_fs, vec![len_f]]).unwrap();
        match prover.verify() {
            Err(_) => {
                println!("Error successfully achieved!");
            }
            _ => assert!(false, "Should be error."),
        }
    }
}
