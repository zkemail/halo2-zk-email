use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    AssignedValue, Context,
};
use halo2_dynamic_sha256::{Field, Sha256DynamicConfig};
use halo2_regex::{AssignedSubstrsResult, SubstrDef, SubstrMatchConfig};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct RegexSha2Result<'a, F: Field> {
    pub substrs: AssignedSubstrsResult<'a, F>,
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
    ) -> Result<RegexSha2Result<'a, F>, Error> {
        let max_input_size = self.sha256_config.max_byte_size;
        // 1. Let's match sub strings!
        let regex_result = self.substr_match_config.match_substrs(ctx, input)?;

        // Let's compute the hash!
        let assigned_hash_result = self.sha256_config.digest(ctx, input)?;
        // Assert that the same input is used in the regex circuit and the sha2 circuit.
        let gate = self.gate();
        let mut input_len_sum = gate.load_zero(ctx);
        for idx in 0..max_input_size {
            let flag = &regex_result.all_enable_flags[idx];
            let regex_input = gate.mul(
                ctx,
                QuantumCell::Existing(flag),
                QuantumCell::Existing(&regex_result.all_characters[idx]),
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
            substrs: regex_result,
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

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.substr_match_config.load(layouter)?;
        self.range().load_lookup_table(layouter)?;
        Ok(())
    }
}
