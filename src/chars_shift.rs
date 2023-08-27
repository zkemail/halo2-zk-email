use crate::*;
use fancy_regex::Regex;
use halo2_base::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::halo2_proofs::{
    circuit::{Cell, Layouter, SimpleFloorPlanner},
    plonk::{Circuit, Column, Error, Instance},
};
use halo2_base::{
    gates::flex_gate::{FlexGateConfig, GateStrategy},
    gates::range::{RangeConfig, RangeStrategy::Vertical},
    utils::PrimeField,
    AssignedValue, Context, ContextParams, SKIP_FIRST_PASS,
};
use halo2_regex::{
    defs::{AllstrRegexDef, RegexDefs, SubstrRegexDef},
    AssignedRegexResult, RegexVerifyConfig,
};
use snark_verifier_sdk::CircuitExt;

#[derive(Debug, Clone)]
pub struct CharsShiftConfig<F: PrimeField> {
    max_chars_size: usize,
    max_substr_size: usize,
    target_substr_id: u64,
    _f: PhantomData<F>,
}

impl<F: PrimeField> CharsShiftConfig<F> {
    pub fn configure(max_chars_size: usize, max_substr_size: usize, target_substr_id: u64) -> Self {
        Self {
            max_chars_size,
            max_substr_size,
            target_substr_id,
            _f: PhantomData,
        }
    }

    pub fn shift<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'b, F>,
        gate: &FlexGateConfig<F>,
        assigned_masked_chars: &[AssignedValue<'a, F>],
        substr_ids: &[AssignedValue<'a, F>],
    ) -> (Vec<AssignedValue<'a, F>>, Vec<AssignedValue<'a, F>>) {
        let mut shift_value = gate.load_zero(ctx);
        let mut is_target_found = gate.load_zero(ctx);
        let mut is_target_vec = vec![];
        for (idx, assigned_substr_id) in substr_ids.iter().enumerate() {
            let is_target = gate.is_equal(ctx, QuantumCell::Existing(assigned_substr_id), QuantumCell::Constant(F::from(self.target_substr_id)));
            is_target_found = gate.select(
                ctx,
                QuantumCell::Constant(F::one()),
                QuantumCell::Existing(&is_target_found),
                QuantumCell::Existing(&is_target),
            );
            shift_value = gate.select(
                ctx,
                QuantumCell::Existing(&shift_value),
                QuantumCell::Constant(F::from((idx + 1) as u64)),
                QuantumCell::Existing(&is_target_found),
            );
            is_target_vec.push(is_target);
        }
        let shifted = self.shift_variable(ctx, gate, assigned_masked_chars, &shift_value);
        let assigned_substr = &shifted[0..self.max_substr_size];
        (assigned_substr.to_vec(), is_target_vec)
    }

    fn shift_variable<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'b, F>,
        gate: &FlexGateConfig<F>,
        inputs: &[AssignedValue<'a, F>],
        shift_value: &AssignedValue<'a, F>,
    ) -> Vec<AssignedValue<'a, F>> {
        debug_assert_eq!(inputs.len(), self.max_chars_size);
        let max_shift_bits: usize = 64 - (self.max_chars_size).leading_zeros() as usize;
        let shift_value_bits = gate.num_to_bits(ctx, shift_value, max_shift_bits);
        let mut prev_tmp = inputs.to_vec();
        let max_len = inputs.len();
        let mut new_tmp = (0..max_len).into_iter().map(|_| gate.load_zero(ctx)).collect::<Vec<AssignedValue<F>>>();
        for log_offset in 0..max_shift_bits {
            for position in 0..max_len {
                let offset = (position + (1 << log_offset)) % max_len;
                let value_offset = gate.select(
                    ctx,
                    QuantumCell::Existing(&prev_tmp[offset]),
                    QuantumCell::Existing(&prev_tmp[position]),
                    QuantumCell::Existing(&shift_value_bits[log_offset]),
                );
                new_tmp[position] = value_offset;
            }
            prev_tmp = new_tmp.to_vec();
        }
        new_tmp
    }
}

// #[derive(Debug, Clone)]
// pub struct CharsShiftInstanceConfig<F: PrimeField> {
//     gate: FlexGateConfig<F>,
//     instance: Column<Instance>,
// }

// #[macro_export]
// macro_rules! impl_chars_shift_circuit {
//     ($circuit_name:ident, $max_chars_size:expr, $num_flex_advice:expr, $num_flex_fixed:expr, $degree:expr) => {
//         #[derive(Debug, Clone)]
//         pub struct $circuit_name<F: PrimeField> {
//             target_substr_id: u8,
//             masked_chars: Vec<u8>,
//             substr_ids: Vec<u8>,
//             max_substr_size: usize,
//             sign_rand: F,
//         }

//         impl<F: PrimeField> Circuit<F> for $circuit_name<F> {
//             type Config = CharsShiftInstanceConfig<F>;
//             type FloorPlanner = SimpleFloorPlanner;

//             fn without_witnesses(&self) -> Self {
//                 Self {
//                     target_substr_id: 0,
//                     masked_chars: vec![0; $max_chars_size],
//                     substr_ids: vec![0; $max_chars_size],
//                     max_substr_size: self.max_substr_size,
//                     sign_rand: F::zero(),
//                 }
//             }

//             fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//                 let gate = FlexGateConfig::configure(meta, GateStrategy::Vertical, &[$num_flex_advice], $num_flex_fixed, 0, $degree);
//                 let instance = meta.instance_column();
//                 meta.enable_equality(instance);
//                 Self::Config { gate, instance }
//             }

//             fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
//                 let mut first_pass = SKIP_FIRST_PASS;
//                 let mut public_input_cells = vec![];
//                 layouter.assign_region(
//                     || "chars shift",
//                     |region| {
//                         if first_pass {
//                             first_pass = false;
//                             return Ok(());
//                         }
//                         let ctx = &mut Context::new(
//                             region,
//                             ContextParams {
//                                 max_rows: config.gate.max_rows,
//                                 num_context_ids: 1,
//                                 fixed_columns: config.gate.constants.clone(),
//                             },
//                         );
//                         let gate = &config.gate;
//                         let mut shift_value = gate.load_zero(ctx);
//                         let mut is_target_found = gate.load_zero(ctx);
//                         let assigned_masked_chars = self
//                             .masked_chars
//                             .iter()
//                             .map(|c| gate.load_witness(ctx, Value::known(F::from(*c as u64))))
//                             .collect_vec();
//                         let assigned_substr_ids = self.substr_ids.iter().map(|c| gate.load_witness(ctx, Value::known(F::from(*c as u64)))).collect_vec();
//                         for (idx, assigned_substr_id) in assigned_substr_ids.iter().enumerate() {
//                             let is_target = gate.is_equal(
//                                 ctx,
//                                 QuantumCell::Existing(assigned_substr_id),
//                                 QuantumCell::Constant(F::from(self.target_substr_id as u64)),
//                             );
//                             is_target_found = gate.select(
//                                 ctx,
//                                 QuantumCell::Constant(F::one()),
//                                 QuantumCell::Existing(&is_target_found),
//                                 QuantumCell::Existing(&is_target),
//                             );
//                             shift_value = gate.select(
//                                 ctx,
//                                 QuantumCell::Existing(&shift_value),
//                                 QuantumCell::Constant(F::from((idx + 1) as u64)),
//                                 QuantumCell::Existing(&is_target_found),
//                             );
//                         }
//                         let shifted = self.shift_variable(ctx, gate, &assigned_masked_chars, &shift_value);
//                         let assigned_substr = &shifted[0..self.max_substr_size];

//                         let sign_rand = gate.load_witness(ctx, Value::known(self.sign_rand));
//                         let poseidon = PoseidonChipBn254_8_58::new(ctx, gate);
//                         let masked_chars_commit = assigned_commit_wtns_bytes(ctx, gate, &poseidon, &sign_rand, &assigned_masked_chars);
//                         let substr_ids_commit = assigned_commit_wtns_bytes(ctx, gate, &poseidon, &sign_rand, &assigned_substr_ids);
//                         let substr_commit = assigned_commit_wtns_bytes(ctx, gate, &poseidon, &sign_rand, &assigned_substr);
//                         public_input_cells.push(masked_chars_commit.cell());
//                         public_input_cells.push(substr_ids_commit.cell());
//                         public_input_cells.push(substr_commit.cell());
//                         Ok(())
//                     },
//                 )?;
//                 for (idx, cell) in public_input_cells.into_iter().enumerate() {
//                     layouter.constrain_instance(cell, config.instance, idx)?;
//                 }
//                 Ok(())
//             }
//         }

//         impl<F: PrimeField> CircuitExt<F> for $circuit_name<F> {
//             fn num_instance(&self) -> Vec<usize> {
//                 vec![3]
//             }

//             fn instances(&self) -> Vec<Vec<F>> {
//                 let masked_chars_commit = value_commit_wtns_bytes(&self.sign_rand, &self.masked_chars);
//                 let substr_ids_commit = value_commit_wtns_bytes(&self.sign_rand, &self.substr_ids);
//                 // let masked_chars_commit = value_commit_wtns_bytes(&self.sign_rand, &expected_masked_chars);
//                 let shift_val = self
//                     .substr_ids
//                     .iter()
//                     .position(|id| *id == self.target_substr_id)
//                     .expect("target substr id must exist");
//                 let substr = &self.masked_chars[shift_val..shift_val + self.max_substr_size];
//                 let substr_commit = value_commit_wtns_bytes(&self.sign_rand, substr);
//                 vec![vec![masked_chars_commit, substr_ids_commit, substr_commit]]
//             }
//         }

//         impl<F: PrimeField> $circuit_name<F> {
//             pub fn new(target_substr_id: u8, masked_chars: Vec<u8>, substr_ids: Vec<u8>, max_substr_size: usize, sign_rand: F) -> Self {
//                 Self {
//                     target_substr_id,
//                     masked_chars,
//                     substr_ids,
//                     max_substr_size,
//                     sign_rand,
//                 }
//             }

//             fn shift_variable<'a, 'b: 'a>(
//                 &self,
//                 ctx: &mut Context<'b, F>,
//                 gate: &FlexGateConfig<F>,
//                 inputs: &[AssignedValue<'a, F>],
//                 shift_value: &AssignedValue<'a, F>,
//             ) -> Vec<AssignedValue<'a, F>> {
//                 debug_assert_eq!(inputs.len(), $max_chars_size);
//                 let max_shift_bits: usize = 64 - ($max_chars_size as usize).leading_zeros() as usize;
//                 let shift_value_bits = gate.num_to_bits(ctx, shift_value, max_shift_bits);
//                 let mut prev_tmp = inputs.to_vec();
//                 let max_len = inputs.len();
//                 let mut new_tmp = (0..max_len).into_iter().map(|_| gate.load_zero(ctx)).collect::<Vec<AssignedValue<F>>>();
//                 for log_offset in 0..max_shift_bits {
//                     for position in 0..max_len {
//                         let offset = (position + (1 << log_offset)) % max_len;
//                         let value_offset = gate.select(
//                             ctx,
//                             QuantumCell::Existing(&prev_tmp[offset]),
//                             QuantumCell::Existing(&prev_tmp[position]),
//                             QuantumCell::Existing(&shift_value_bits[log_offset]),
//                         );
//                         new_tmp[position] = value_offset;
//                     }
//                     prev_tmp = new_tmp.to_vec();
//                 }
//                 new_tmp
//             }
//         }
//     };
// }

// // impl_chars_shift_circuit!(DummyCharsShiftCircuit, 128, 1, 0, 8);
// impl_chars_shift_circuit!(
//     CharsShiftBodyHashCircuit,
//     default_config_params().header_config.as_ref().unwrap().max_variable_byte_size,
//     default_config_params().num_flex_advice,
//     default_config_params().num_flex_fixed,
//     default_config_params().degree as usize
// );
