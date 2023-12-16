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

/// Configuration to shift the input characters by a variable number of bytes, used to extract a target substring from the masked characters.
#[derive(Debug, Clone)]
pub struct CharsShiftConfig<F: PrimeField> {
    /// The maximum number of characters in the input string.
    pub max_chars_size: usize,
    /// The maximum number of characters in the target substring.
    pub max_substr_size: usize,
    /// The target substring id.
    pub target_substr_id: u64,
    _f: PhantomData<F>,
}

impl<F: PrimeField> CharsShiftConfig<F> {
    /// Construct a new [`CharsShiftConfig`].
    ///
    /// # Arguments
    /// * `max_chars_size` - the maximum number of characters in the input string.
    /// * `max_substr_size` - the maximum number of characters in the target substring.
    /// * `target_substr_id` - the target substring id.
    /// # Return values
    /// Return a new [`CharsShiftConfig`].
    pub fn configure(max_chars_size: usize, max_substr_size: usize, target_substr_id: u64) -> Self {
        Self {
            max_chars_size,
            max_substr_size,
            target_substr_id,
            _f: PhantomData,
        }
    }

    /// Shift the masked characters to extract a substring of the target substring id.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `gate` - a configuration of [`FlexGateConfig`].
    /// * `assigned_masked_chars` - a list of the assigned masked characters.
    /// * `assigned_substr_ids` - a list of the assigned substring ids.
    /// # Return values
    /// Return a tuple of the assigned substring characters and a list of flags that indicates whether each character has the target substring id or not.
    pub fn shift<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'b, F>,
        gate: &FlexGateConfig<F>,
        assigned_masked_chars: &[AssignedValue<'a, F>],
        assigned_substr_ids: &[AssignedValue<'a, F>],
    ) -> (Vec<AssignedValue<'a, F>>, Vec<AssignedValue<'a, F>>) {
        let mut shift_value = gate.load_zero(ctx);
        let mut is_target_found = gate.load_zero(ctx);
        let mut is_target_vec = vec![];
        for (idx, assigned_substr_id) in assigned_substr_ids.iter().enumerate() {
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
        gate.assert_equal(ctx, QuantumCell::Existing(&is_target_found), QuantumCell::Constant(F::one()));
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
        #[cfg(target_pointer_width = "64")]
        let usize_bits = 64;
        #[cfg(target_pointer_width = "32")]
        let usize_bits = 32;
        let max_shift_bits: usize = (usize_bits - (self.max_chars_size).leading_zeros()) as usize;
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
