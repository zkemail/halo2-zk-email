mod macros;
pub mod regex_sha2;
pub mod regex_sha2_base64;
use crate::regex_sha2::RegexSha2Config;
use halo2_base::halo2_proofs::circuit::{Region, SimpleFloorPlanner};
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions},
    utils::PrimeField,
    Context,
};
use halo2_dynamic_sha256::Field;
use halo2_regex::{AssignedSubstrsResult, RegexDef, SubstrDef};
use halo2_rsa::{
    AssignedRSAPublicKey, AssignedRSASignature, RSAConfig, RSAInstructions, RSAPublicKey,
    RSASignature,
};
pub use macros::*;
use regex_sha2_base64::RegexSha2Base64Config;

#[derive(Debug, Clone)]
pub struct EmailVerifyConfig<F: Field> {
    header_processer: RegexSha2Config<F>,
    body_processer: RegexSha2Base64Config<F>,
    rsa_config: RSAConfig<F>,
}

impl<F: Field> EmailVerifyConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        num_sha2_compression_per_column: usize,
        range_config: RangeConfig<F>,
        header_max_byte_size: usize,
        header_regex_def: RegexDef,
        body_hash_substr_def: SubstrDef,
        header_substr_defs: Vec<SubstrDef>,
        body_max_byte_size: usize,
        body_regex_def: RegexDef,
        body_substr_defs: Vec<SubstrDef>,
        public_key_bits: usize,
    ) -> Self {
        let header_substr_defs = [vec![body_hash_substr_def], header_substr_defs].concat();
        let header_processer = RegexSha2Config::configure(
            meta,
            header_max_byte_size,
            num_sha2_compression_per_column,
            range_config.clone(),
            header_regex_def,
            header_substr_defs,
        );
        let body_processer = RegexSha2Base64Config::configure(
            meta,
            body_max_byte_size,
            num_sha2_compression_per_column,
            range_config.clone(),
            body_regex_def,
            body_substr_defs,
        );
        let biguint_config = halo2_rsa::BigUintConfig::construct(range_config, 64);
        let rsa_config = RSAConfig::construct(biguint_config, public_key_bits, 5);
        Self {
            header_processer,
            body_processer,
            rsa_config,
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
        body_bytes: &[u8],
        public_key: &AssignedRSAPublicKey<'v, F>,
        signature: &AssignedRSASignature<'v, F>,
    ) -> Result<(AssignedSubstrsResult<'a, F>, AssignedSubstrsResult<'a, F>), Error> {
        let gate = self.gate();

        // 1. Extract sub strings in the body and compute the base64 encoded hash of the body.
        let body_result = self.body_processer.match_hash_and_base64(ctx, body_bytes)?;

        // 2. Extract sub strings in the header, which includes the body hash, and compute the raw hash of the header.
        let header_result = self.header_processer.match_and_hash(ctx, header_bytes)?;

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
        let hash_body_substr = &header_result.substrs.substrs_bytes[0];
        let body_encoded_hash = body_result.encoded_hash;
        debug_assert_eq!(hash_body_substr.len(), body_encoded_hash.len());
        for (substr_byte, encoded_byte) in
            hash_body_substr.iter().zip(body_encoded_hash.into_iter())
        {
            ctx.region
                .constrain_equal(substr_byte.cell(), encoded_byte.cell())?;
        }
        gate.assert_is_const(
            ctx,
            &header_result.substrs.substrs_length[0],
            F::from(32 * 4 / 3 + 4),
        );
        Ok((header_result.substrs, body_result.substrs))
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.header_processer.load(layouter)?;
        self.body_processer.load(layouter)?;
        self.rsa_config.range().load_lookup_table(layouter)?;
        Ok(())
    }

    pub fn finalize(&self, ctx: &mut Context<F>) {
        self.header_processer.finalize(ctx);
    }

    pub fn new_context<'a, 'b>(&'b self, region: Region<'a, F>) -> Context<'a, F> {
        self.header_processer.new_context(region)
    }

    pub fn range(&self) -> &RangeConfig<F> {
        self.header_processer.range()
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        self.header_processer.gate()
    }
}

// macro_rules!  {
//     () => {

//     };
// }

// #[derive(Debug, Clone)]
// pub struct EmailVerifyCircuit<F: Field> {
//     max_byte_size: usize,
//     num_sha2_compression_per_column: usize,
//     range_config: RangeConfig<F>,
//     header_state_lookup: HashMap<(u8, u64), u64>,
//     header_first_state: u64,
//     header_accepted_state_vals: Vec<u64>,
//     header_substr_defs: Vec<SubstrDef>,
//     body_state_lookup: HashMap<(u8, u64), u64>,
//     body_first_state: u64,
//     body_accepted_state_vals: Vec<u64>,
//     body_substr_defs: Vec<SubstrDef>,
//     public_key_bits: usize,
// }

// impl<F: Field> Circuit<F> for EmailVerifyCircuit<F> {
//     type Config = EmailVerifyConfig<F>;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//         Self::Config::configure()
//     }
// }

// impl<F: Field> EmailVerifyCircuit<F> {
//     const HEADER_REGEX_FILEPATH: &'static str = "./test_regexes/email_header"
// }

#[cfg(test)]
mod test {
    use super::*;
    use halo2_base::halo2_proofs::{
        circuit::{floor_planner::V1, Cell, SimpleFloorPlanner},
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Fr, G1},
        plonk::{Any, Circuit, Column, Instance},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
    use mail_auth::dkim;
    use sha2::{self, Digest, Sha256};

    // impl_email_verify_circuit!(
    //     TestEmailVerify2048Config,
    //     TestEmailVerify2048Circuit,
    //     2,
    //     128,
    // );
}
