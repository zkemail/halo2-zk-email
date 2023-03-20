use halo2_base::halo2_proofs::{circuit::Value, plonk::Error};
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, PrimeField},
    AssignedValue, Context,
};
use halo2_dynamic_sha256::{
    AssignedHashResult, Field, Sha256CompressionConfig, Sha256DynamicConfig,
};
use halo2_ecc::bigint::{
    big_is_equal, big_is_zero, big_less_than, carry_mod, mul_no_carry, negative, select, sub,
    CRTInteger, FixedCRTInteger, FixedOverflowInteger, OverflowInteger,
};
use halo2_regex::{AssignedAllString, AssignedSubstrResult, SubstrDef, SubstrMatchConfig};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};

#[derive(Debug, Clone)]
pub struct RegexSha2Base64Config<F: Field> {
    sha256_config: Sha256DynamicConfig<F>,
    substr_match_config: SubstrMatchConfig<F>,
}

impl<F: Field> RegexSha2Base64Config<F> {
    pub fn construct(
        sha256_config: Sha256DynamicConfig<F>,
        substr_match_config: SubstrMatchConfig<F>,
    ) -> Self {
        Self {
            sha256_config,
            substr_match_config,
        }
    }

    pub fn match_hash_and_base64(
        &self,
        ctx: &mut Context<F>,
        input: &[u8],
        states: &[u64],
        substr_positions_array: &[&[u64]],
        substr_defs: &[SubstrDef],
    ) -> Result<(), Error> {
        let max_input_size = self.sha256_config.max_byte_size;
        // 1. Let's match sub strings!
        let assigned_all_strings =
            self.substr_match_config
                .assign_all_string(ctx, input, states, max_input_size)?;
        let mut assigned_substrs = Vec::new();
        for (substr_def, substr_positions) in substr_defs
            .into_iter()
            .zip(substr_positions_array.into_iter())
        {
            let assigned_substr = self.substr_match_config.match_substr(
                ctx,
                substr_def,
                substr_positions,
                &assigned_all_strings,
            )?;
            assigned_substrs.push(assigned_substr);
        }

        // Let's compute the hash!
        let assigned_hash_result = self.sha256_config.digest(ctx, input)?;
        // Assert that the same input is used in the regex circuit and the sha2 circuit.
        let gate = self.gate();
        let mut input_len_sum = gate.load_zero(ctx);
        for idx in 0..max_input_size {
            let flag = &assigned_all_strings.enable_flags[idx];
            let regex_input = gate.mul(
                ctx,
                QuantumCell::Existing(flag),
                QuantumCell::Existing(&assigned_all_strings.characters[idx]),
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

        Ok(())
    }

    pub fn range(&self) -> &RangeConfig<F> {
        self.sha256_config.range()
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        self.range().gate()
    }
}
