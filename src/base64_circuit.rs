use crate::wtns_commit::{
    assigned_commit_wtns_bytes,
    poseidon_circuit::{HasherChip, PoseidonChipBn254_8_58},
    value_commit_wtns_bytes,
};
use crate::*;
use base64::{engine::general_purpose, Engine as _};
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
use halo2_base64::Base64Config;

use snark_verifier_sdk::CircuitExt;

#[derive(Debug, Clone)]
pub struct Base64InstanceConfig<F: PrimeField> {
    inner: Base64Config<F>,
    gate: FlexGateConfig<F>,
    instance: Column<Instance>,
}

#[macro_export]
macro_rules! impl_base64_circuit {
    ($circuit_name:ident, $num_flex_advice:expr, $num_flex_fixed:expr, $degree:expr) => {
        #[derive(Debug, Clone)]
        struct $circuit_name<F: PrimeField> {
            input: Vec<u8>,
            sign_rand: F,
        }

        impl<F: PrimeField> Circuit<F> for $circuit_name<F> {
            type Config = Base64InstanceConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self {
                    input: vec![0; self.input.len()],
                    sign_rand: F::zero(),
                }
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let gate = FlexGateConfig::configure(meta, GateStrategy::Vertical, &[$num_flex_advice], $num_flex_fixed, 0, $degree);
                let inner = Base64Config::configure(meta);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                Self::Config { gate, inner, instance }
            }

            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
                config.inner.load(&mut layouter)?;
                let mut first_pass = SKIP_FIRST_PASS;
                let mut public_input_cells = vec![];
                layouter.assign_region(
                    || "base64",
                    |region| {
                        if first_pass {
                            first_pass = false;
                            return Ok(());
                        }
                        let ctx = &mut Context::new(
                            region,
                            ContextParams {
                                max_rows: config.gate.max_rows,
                                num_context_ids: 1,
                                fixed_columns: config.gate.constants.clone(),
                            },
                        );
                        debug_assert_eq!(self.input.len(), 32);
                        let mut hash_base64 = Vec::new();
                        hash_base64.resize(44, 0);
                        let bytes_written = general_purpose::STANDARD
                            .encode_slice(&self.input, &mut hash_base64)
                            .expect("fail to convert the hash bytes into the base64 strings");
                        debug_assert_eq!(bytes_written, 44);
                        let base64_result = config.inner.assign_values(&mut ctx.region, &hash_base64)?;
                        debug_assert_eq!(base64_result.decoded.len(), 32);

                        let gate = &config.gate;
                        let poseidon = PoseidonChipBn254_8_58::new(ctx, gate);
                        let sign_rand = gate.load_witness(ctx, Value::known(self.sign_rand));
                        let mut input = vec![];
                        for assigned_cell in base64_result.decoded.iter() {
                            let value = assigned_cell.value().map(|v| *v);
                            let assigned_value = gate.load_witness(ctx, value);
                            ctx.region.constrain_equal(assigned_cell.cell(), assigned_value.cell())?;
                            input.push(assigned_value);
                        }
                        let mut output = vec![];
                        for assigned_cell in base64_result.encoded.iter() {
                            let value = assigned_cell.value().map(|v| *v);
                            let assigned_value = gate.load_witness(ctx, value);
                            ctx.region.constrain_equal(assigned_cell.cell(), assigned_value.cell())?;
                            output.push(assigned_value);
                        }
                        let input_commit = assigned_commit_wtns_bytes(ctx, gate, &poseidon, &sign_rand, &input);
                        let output_commit = assigned_commit_wtns_bytes(ctx, gate, &poseidon, &sign_rand, &output);
                        public_input_cells.push(input_commit.cell());
                        public_input_cells.push(output_commit.cell());
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
                vec![2]
            }

            fn instances(&self) -> Vec<Vec<F>> {
                let input_commit = value_commit_wtns_bytes(&self.sign_rand, &self.input);
                let hash_commit = value_commit_wtns_bytes(&self.sign_rand, &Sha256::digest(&self.input).to_vec());
                vec![vec![input_commit, hash_commit]]
            }
        }

        impl<F: PrimeField> $circuit_name<F> {
            pub fn new(input: Vec<u8>, sign_rand: F) -> Self {
                Self { input, sign_rand }
            }
        }
    };
}

impl_base64_circuit!(DummyBase64Circuit, 1, 1, 1);
