pub mod regex_sha2;
pub mod regex_sha2_base64;
use crate::regex_sha2::{RegexSha2Config, RegexSha2Result};
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use halo2_base::halo2_proofs::{
    circuit::{AssignedCell, Value},
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
use halo2_rsa::{
    AssignedRSAPublicKey, AssignedRSASignature, RSAConfig, RSAInstructions, RSAPublicKey,
    RSASignature,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};
use regex_sha2_base64::{RegexSha2Base64Config, RegexSha2Base64Result};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct EmailVerifyConfig<F: Field> {
    header_processer: RegexSha2Config<F>,
    body_processer: RegexSha2Base64Config<F>,
    rsa_config: RSAConfig<F>,
    header_substr_defs: Vec<SubstrDef>,
    body_substr_defs: Vec<SubstrDef>,
    body_hash_substr_def: SubstrDef,
}

impl<F: Field> EmailVerifyConfig<F> {
    pub fn construct(
        header_processer: RegexSha2Config<F>,
        body_processer: RegexSha2Base64Config<F>,
        rsa_config: RSAConfig<F>,
        header_substr_defs: Vec<SubstrDef>,
        body_substr_defs: Vec<SubstrDef>,
        body_hash_substr_def: SubstrDef,
    ) -> Self {
        Self {
            header_processer,
            body_processer,
            rsa_config,
            header_substr_defs,
            body_substr_defs,
            body_hash_substr_def,
        }
    }

    pub fn assign_public_key<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        public_key: RSAPublicKey<F>,
    ) -> Result<AssignedRSAPublicKey<'v, F>, Error> {
        self.rsa_config.assign_public_key(ctx, public_key)
    }

    pub fn assign_signature<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        signature: RSASignature<F>,
    ) -> Result<AssignedRSASignature<'v, F>, Error> {
        self.rsa_config.assign_signature(ctx, signature)
    }

    pub fn verify_email<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        header_bytes: &[u8],
        header_regex_states: &[u64],
        header_substr_positions_array: &[&[u64]],
        body_bytes: &[u8],
        body_regex_states: &[u64],
        body_substr_positions_array: &[&[u64]],
        body_hash_positions_array: &[u64],
        public_key: &AssignedRSAPublicKey<'v, F>,
        signature: &AssignedRSASignature<'v, F>,
    ) -> Result<
        (
            Vec<AssignedSubstrResult<'a, F>>,
            Vec<AssignedSubstrResult<'a, F>>,
        ),
        Error,
    > {
        debug_assert_eq!(
            header_substr_positions_array.len(),
            self.header_substr_defs.len()
        );
        debug_assert_eq!(
            body_substr_positions_array.len(),
            self.body_substr_defs.len()
        );
        let gate = self.gate();

        // 1. Extract sub strings in the body and compute the base64 encoded hash of the body.
        let body_result = self.body_processer.match_hash_and_base64(
            ctx,
            body_bytes,
            body_regex_states,
            body_substr_positions_array,
            &self.body_substr_defs,
        )?;

        // 2. Extract sub strings in the header, which includes the body hash, and compute the raw hash of the header.
        let mut header_substr_defs = vec![self.body_hash_substr_def.clone()];
        for header_def in self.header_substr_defs.iter() {
            header_substr_defs.push(header_def.clone());
        }
        let mut header_substr_positions_array_all = vec![body_hash_positions_array];
        for array in header_substr_positions_array.into_iter() {
            header_substr_positions_array_all.push(array);
        }
        let header_result = self.header_processer.match_and_hash(
            ctx,
            header_bytes,
            header_regex_states,
            &header_substr_positions_array_all,
            &self.header_substr_defs,
        )?;

        // 3. Verify the rsa signature.
        let mut hashed_bytes = header_result.hash_bytes;
        hashed_bytes.reverse();
        let bytes_bits = hashed_bytes.len() * 8;
        let limb_bits = self.rsa_config.biguint_config().limb_bits;
        let limb_bytes = limb_bits / 8;
        let mut hashed_u64s = vec![];
        let bases = (0..limb_bytes)
            .map(|i| F::from((1u64 << (8 * i)) as u64))
            .map(QuantumCell::Constant)
            .collect::<Vec<QuantumCell<F>>>();
        for i in 0..(bytes_bits / limb_bits) {
            let left = hashed_bytes[limb_bytes * i..limb_bytes * (i + 1)]
                .iter()
                .map(QuantumCell::Existing)
                .collect::<Vec<QuantumCell<F>>>();
            let sum = gate.inner_product(ctx, left, bases.clone());
            hashed_u64s.push(sum);
        }
        let is_sign_valid =
            self.rsa_config
                .verify_pkcs1v15_signature(ctx, public_key, &hashed_u64s, signature)?;
        gate.assert_is_const(ctx, &is_sign_valid, F::one());

        // 4. Check that the encoded hash value is equal to the value in the email header.
        let hash_body_substr = &header_result.substrs[0];
        let body_encoded_hash = body_result.encoded_hash;
        debug_assert_eq!(
            hash_body_substr.assigned_bytes.len(),
            body_encoded_hash.len()
        );
        for (substr_byte, encoded_byte) in hash_body_substr
            .assigned_bytes
            .iter()
            .zip(body_encoded_hash.into_iter())
        {
            ctx.region
                .constrain_equal(substr_byte.cell(), encoded_byte.cell())?;
        }
        gate.assert_is_const(
            ctx,
            &hash_body_substr.assigned_length,
            F::from(32 * 4 / 3 + 4),
        );
        Ok((header_result.substrs[1..].to_vec(), body_result.substrs))
    }

    pub fn range(&self) -> &RangeConfig<F> {
        self.header_processer.range()
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        self.header_processer.gate()
    }
}
