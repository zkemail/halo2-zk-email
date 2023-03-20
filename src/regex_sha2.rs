use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use halo2_base::halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::Error,
};
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, PrimeField},
    AssignedValue, Context,
};
use halo2_base64::{AssignedBase64Result, Base64Config};
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
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct RegexSha2Result<'a, F: Field> {
    pub substrs: Vec<AssignedSubstrResult<'a, F>>,
    pub hash_bytes: Vec<AssignedValue<'a, F>>,
}

#[derive(Debug, Clone)]
pub struct RegexSha2Config<F: Field> {
    pub(crate) sha256_config: Sha256DynamicConfig<F>,
    pub(crate) substr_match_config: SubstrMatchConfig<F>,
}

impl<F: Field> RegexSha2Config<F> {
    pub fn construct(
        sha256_config: Sha256DynamicConfig<F>,
        substr_match_config: SubstrMatchConfig<F>,
    ) -> Self {
        Self {
            sha256_config,
            substr_match_config,
        }
    }

    pub fn match_and_hash<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        input: &[u8],
        states: &[u64],
        substr_positions_array: &[&[u64]],
        substr_defs: &[SubstrDef],
    ) -> Result<RegexSha2Result<'a, F>, Error> {
        let max_input_size = self.sha256_config.max_byte_size;
        let mut input = input.to_vec();
        let mut states = states.to_vec();
        debug_assert_eq!(input.len(), states.len());
        for _ in 0..(max_input_size - input.len()) {
            input.push(0);
            states.push(0);
        }
        // 1. Let's match sub strings!
        let assigned_all_strings =
            self.substr_match_config
                .assign_all_string(ctx, &input, &states, max_input_size)?;
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
        let assigned_hash_result = self.sha256_config.digest(ctx, &input)?;
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

        let actual_hash = Sha256::digest(input).to_vec();
        debug_assert_eq!(actual_hash.len(), 32);

        let result = RegexSha2Result {
            substrs: assigned_substrs,
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

    pub fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        regex_lookups: &[&[u64]],
        accepted_states: &[u64],
    ) -> Result<(), Error> {
        self.substr_match_config
            .load(layouter, regex_lookups, accepted_states)?;
        self.range().load_lookup_table(layouter)?;
        Ok(())
    }
}
