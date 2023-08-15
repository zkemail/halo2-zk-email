use crate::wtns_commit::{
    assigned_commit_wtns_bytes,
    poseidon_circuit::{HasherChip, PoseidonChipBn254_8_58},
    value_commit_wtns_bytes,
};
use crate::*;
use halo2_base::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::halo2_proofs::{
    circuit::{Cell, Layouter, SimpleFloorPlanner},
    plonk::{Circuit, Column, Error, Instance},
};
use halo2_base::{
    gates::flex_gate::{FlexGateConfig, GateStrategy},
    gates::range::{RangeConfig, RangeStrategy::Vertical},
    utils::PrimeField,
    Context, ContextParams, SKIP_FIRST_PASS,
};
use halo2_regex::{
    defs::{AllstrRegexDef, RegexDefs, SubstrRegexDef},
    AssignedRegexResult, RegexVerifyConfig,
};
use snark_verifier_sdk::CircuitExt;

#[derive(Debug, Clone)]
struct RegexInstanceConfig<F: PrimeField> {
    inner: RegexVerifyConfig<F>,
    instance: Column<Instance>,
}

#[macro_export]
macro_rules! impl_regex_circuit {
    ($circuit_name:ident, $max_chars_size:expr, $num_flex_advice:expr, $num_flex_fixed:expr, $degree:expr) => {
        #[derive(Debug, Clone)]
        struct $circuit_name<F: PrimeField> {
            input: Vec<u8>,
            regex_def: RegexDefs,
            substr_regexes: Vec<Vec<String>>,
            sign_rand: F,
        }

        impl<F: PrimeField> Circuit<F> for $circuit_name<F> {
            type Config = RegexInstanceConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self {
                    input: vec![0; self.input.len()],
                    regex_def: self.regex_def.clone(),
                    substr_regexes: self.substr_regexes.clone(),
                    sign_rand: F::zero(),
                }
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let gate = FlexGateConfig::configure(meta, GateStrategy::Vertical, &[$num_flex_advice], $num_flex_fixed, 0, $degree);
                let inner = RegexVerifyConfig::configure(meta, $max_chars_size, gate, 1, 0, u64::MAX);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                Self::Config { inner, instance }
            }

            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
                config.inner.load(&mut layouter, &[self.regex_def.clone()])?;
                let mut first_pass = SKIP_FIRST_PASS;
                let mut public_input_cells = vec![];
                layouter.assign_region(
                    || "regex",
                    |region| {
                        if first_pass {
                            first_pass = false;
                            return Ok(());
                        }
                        let ctx = &mut Context::new(
                            region,
                            ContextParams {
                                max_rows: config.inner.gate().max_rows,
                                num_context_ids: 1,
                                fixed_columns: config.inner.gate().constants.clone(),
                            },
                        );
                        let result = config.inner.match_substrs(ctx, &self.input, &[self.regex_def.clone()])?;

                        let gate = config.inner.gate();
                        let poseidon = PoseidonChipBn254_8_58::new(ctx, gate);
                        let sign_rand = gate.load_witness(ctx, Value::known(self.sign_rand));
                        let actual_input = (0..$max_chars_size)
                            .map(|idx| {
                                gate.mul(
                                    ctx,
                                    QuantumCell::Existing(&result.all_characters[idx]),
                                    QuantumCell::Existing(&result.all_enable_flags[idx]),
                                )
                            })
                            .collect_vec();
                        let input_commit = assigned_commit_wtns_bytes(ctx, gate, &poseidon, &sign_rand, &actual_input);
                        let substr_ids_commit = assigned_commit_wtns_bytes(ctx, gate, &poseidon, &sign_rand, &result.all_substr_ids);
                        let masked_chars_commit = assigned_commit_wtns_bytes(ctx, gate, &poseidon, &sign_rand, &result.masked_characters);
                        public_input_cells.push(input_commit.cell());
                        public_input_cells.push(substr_ids_commit.cell());
                        public_input_cells.push(masked_chars_commit.cell());
                        Ok(())
                    },
                )?;
                for (idx, cell) in public_input_cells.into_iter().enumerate() {
                    layouter.constrain_instance(cell, config.instance, idx)?;
                }
                Ok(())
            }
        }

        impl<F: PrimeField> CircuitExt<F> for $circuit_name<F> {
            fn num_instance(&self) -> Vec<usize> {
                vec![3]
            }

            fn instances(&self) -> Vec<Vec<F>> {
                let input_str = String::from_utf8(self.input.clone()).unwrap();
                let substrs = self.substr_regexes.iter().map(|regexes| get_substr(&input_str, regexes)).collect_vec();
                let mut expected_masked_chars = vec![0u8; $max_chars_size];
                let mut expected_substr_ids = vec![0u8; $max_chars_size]; // We only support up to 256 substring patterns.
                for (substr_idx, m) in substrs.iter().enumerate() {
                    if let Some((start, chars)) = m {
                        for (idx, char) in chars.as_bytes().iter().enumerate() {
                            expected_masked_chars[start + idx] = *char;
                            expected_substr_ids[start + idx] = substr_idx as u8 + 1;
                        }
                    }
                }
                let padding_size = $max_chars_size - self.input.len();
                let input_bytes = vec![&self.input[..], &vec![0; padding_size]].concat();
                let input_commit = value_commit_wtns_bytes(&self.sign_rand, &input_bytes);
                let substr_ids_commit = value_commit_wtns_bytes(&self.sign_rand, &expected_substr_ids);
                let masked_chars_commit = value_commit_wtns_bytes(&self.sign_rand, &expected_masked_chars);
                vec![vec![input_commit, substr_ids_commit, masked_chars_commit]]
            }
        }

        impl<F: PrimeField> $circuit_name<F> {
            pub fn new(input: Vec<u8>, regex_def: RegexDefs, substr_regexes: Vec<Vec<String>>, sign_rand: F) -> Self {
                Self {
                    input,
                    regex_def,
                    substr_regexes,
                    sign_rand,
                }
            }
        }
    };
}

// impl_base64_circuit!(DummyBase64Circuit, 1, 1, 1);
impl_regex_circuit!(DummyRegexCircuit, 1, 1, 1, 1);
