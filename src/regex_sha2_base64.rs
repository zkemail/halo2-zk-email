use crate::regex_sha2::RegexSha2Config;
use base64::{engine::general_purpose, Engine as _};
use halo2_base::halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::Error,
};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, RangeInstructions},
    Context,
};
use halo2_base64::Base64Config;
use halo2_dynamic_sha256::Field;
use halo2_regex::{AssignedSubstrsResult, SubstrDef};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct RegexSha2Base64Result<'a, F: Field> {
    pub substrs: AssignedSubstrsResult<'a, F>,
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
    ) -> Result<RegexSha2Base64Result<'a, F>, Error> {
        let regex_sha2_result = self.regex_sha2.match_and_hash(ctx, input)?;

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

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.regex_sha2.load(layouter)?;
        self.base64_config.load(layouter)?;
        Ok(())
    }
}
