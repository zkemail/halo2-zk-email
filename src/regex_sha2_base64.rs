use crate::regex_sha2::{RegexSha2Config, RegexSha2Result};
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
pub struct RegexSha2Base64Result<'a, F: Field> {
    pub substrs: Vec<AssignedSubstrResult<'a, F>>,
    pub encoded_hash: Vec<AssignedCell<F, F>>,
}

#[derive(Debug, Clone)]
pub struct RegexSha2Base64Config<F: Field> {
    pub(crate) regex_sha2: RegexSha2Config<F>,
    pub(crate) base64_config: Base64Config<F>,
}

impl<F: Field> RegexSha2Base64Config<F> {
    pub fn construct(regex_sha2: RegexSha2Config<F>, base64_config: Base64Config<F>) -> Self {
        Self {
            regex_sha2,
            base64_config,
        }
    }

    pub fn match_hash_and_base64<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        input: &[u8],
        states: &[u64],
        substr_positions_array: &[&[u64]],
        substr_defs: &[SubstrDef],
    ) -> Result<RegexSha2Base64Result<'a, F>, Error> {
        let regex_sha2_result = self.regex_sha2.match_and_hash(
            ctx,
            input,
            states,
            substr_positions_array,
            substr_defs,
        )?;

        let actual_hash = Sha256::digest(input).to_vec();
        debug_assert_eq!(actual_hash.len(), 32);
        let mut hash_base64 = Vec::new();
        hash_base64.resize(actual_hash.len() * 4 / 3 + 4, 0);
        let bytes_written = general_purpose::STANDARD
            .encode_slice(&actual_hash, &mut hash_base64)
            .expect("fail to convert the hash bytes into the base64 strings");
        debug_assert_eq!(bytes_written, actual_hash.len() * 4 / 3 + 4);
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

    pub fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        regex_lookups: &[&[u64]],
        accepted_states: &[u64],
    ) -> Result<(), Error> {
        self.regex_sha2
            .load(layouter, regex_lookups, accepted_states)?;
        self.base64_config.load(layouter)?;
        Ok(())
    }
}
