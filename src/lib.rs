pub mod regex_sha2_base64;
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
use halo2_rsa::RSAConfig;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};
use regex_sha2_base64::{RegexSha2Base64Config, RegexSha2Base64Result};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct EmailVerifyConfig<F: Field> {
    regex_sha2_base64: RegexSha2Base64Config<F>,
    rsa_config: RSAConfig<F>,
}

impl<F: Field> EmailVerifyConfig<F> {
    pub fn construct(
        regex_sha2_base64: RegexSha2Base64Config<F>,
        rsa_config: RSAConfig<F>,
    ) -> Self {
        Self {
            regex_sha2_base64,
            rsa_config,
        }
    }

    pub fn range(&self) -> &RangeConfig<F> {
        self.regex_sha2_base64.range()
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        self.regex_sha2_base64.gate()
    }
}
