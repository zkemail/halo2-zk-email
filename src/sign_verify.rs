use std::marker::PhantomData;

use crate::wtns_commit::{
    assigned_commit_wtns_bytes,
    poseidon_circuit::{poseidon_hash_fields, HasherChip, PoseidonChipBn254_8_58},
    value_commit_wtns_bytes,
};
use halo2_base::halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Instance};
use halo2_base::halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::PrimeField,
    Context,
};
use halo2_base::{halo2_proofs::circuit::SimpleFloorPlanner, utils::decompose_biguint};
use halo2_base::{AssignedValue, QuantumCell, SKIP_FIRST_PASS};
use halo2_rsa::{AssignedRSAPublicKey, AssignedRSASignature, RSAConfig, RSAInstructions, RSAPubE, RSAPublicKey, RSASignature};
use itertools::Itertools;
use num_bigint::BigUint;
use snark_verifier_sdk::CircuitExt;

/// Output type definition of [`SignVerifyConfig`].
#[derive(Debug, Clone)]
pub struct SignVerifyResult<'a, F: PrimeField> {
    pub assigned_public_key: AssignedRSAPublicKey<'a, F>,
    pub assigned_signature: AssignedRSASignature<'a, F>,
}

/// Configuration to verify the rsa signature for the given hash and public key.  
#[derive(Debug, Clone)]
pub struct SignVerifyConfig<F: PrimeField> {
    /// Configuration for [`RSAConfig`].
    pub rsa_config: RSAConfig<F>,
}

impl<F: PrimeField> SignVerifyConfig<F> {
    pub fn configure(range_config: RangeConfig<F>, public_key_bits: usize) -> Self {
        let biguint_config = halo2_rsa::BigUintConfig::construct(range_config, Self::LIMB_BITS);
        let rsa_config = RSAConfig::construct(biguint_config, public_key_bits, 5);
        Self { rsa_config }
    }

    pub fn range(&self) -> &RangeConfig<F> {
        self.rsa_config.range()
    }

    pub fn assign_public_key<'v>(&self, ctx: &mut Context<'v, F>, public_key: RSAPublicKey<F>) -> Result<AssignedRSAPublicKey<'v, F>, Error> {
        self.rsa_config.assign_public_key(ctx, public_key)
    }

    pub fn assign_signature<'v>(&self, ctx: &mut Context<'v, F>, signature: RSASignature<F>) -> Result<AssignedRSASignature<'v, F>, Error> {
        self.rsa_config.assign_signature(ctx, signature)
    }

    pub fn verify_signature<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        hash_bytes: &[AssignedValue<'v, F>],
        public_key_n: BigUint,
        signature: BigUint,
    ) -> Result<SignVerifyResult<'a, F>, Error> {
        let e = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
        let public_key = RSAPublicKey::<F>::new(Value::known(public_key_n), e);
        let signature = RSASignature::<F>::new(Value::known(signature));
        let gate = self.rsa_config.gate();
        let mut hash_bytes = hash_bytes.to_vec();
        hash_bytes.reverse();
        let bytes_bits = hash_bytes.len() * 8;
        let limb_bits = self.rsa_config.biguint_config().limb_bits;
        let limb_bytes = limb_bits / 8;
        let mut hashed_u64s = vec![];
        let bases = (0..limb_bytes)
            .map(|i| F::from((1u64 << (8 * i)) as u64))
            .map(QuantumCell::Constant)
            .collect::<Vec<QuantumCell<F>>>();
        for i in 0..(bytes_bits / limb_bits) {
            let left = hash_bytes[limb_bytes * i..limb_bytes * (i + 1)]
                .iter()
                .map(QuantumCell::Existing)
                .collect::<Vec<QuantumCell<F>>>();
            let sum = gate.inner_product(ctx, left, bases.clone());
            hashed_u64s.push(sum);
        }
        let public_key = self.assign_public_key(ctx, public_key)?;
        let signature = self.assign_signature(ctx, signature)?;
        let is_sign_valid = self.rsa_config.verify_pkcs1v15_signature(ctx, &public_key, &hashed_u64s, &signature)?;
        gate.assert_is_const(ctx, &is_sign_valid, F::one());

        Ok(SignVerifyResult {
            assigned_public_key: public_key,
            assigned_signature: signature,
        })
    }
}

impl<F: PrimeField> SignVerifyConfig<F> {
    pub const DEFAULT_E: u32 = 65537;
    pub const LIMB_BITS: usize = 64;
}

/// Configuration parameters for [`SignVerifyConfig`].
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SignVerifyParams {
    /// The bits of RSA public key.
    pub public_key_bits: usize,
    /// A flag whether the public key is hidden.
    pub hide_public_key: Option<bool>,
}

#[macro_export]
macro_rules! impl_sign_verify_circuit {
    ($circuit_name:ident, $num_flex_advice:expr, $num_range_lookup_advice:expr, $range_lookup_bits:expr, $degree:expr, $public_key_bits:expr, $hide_public_key:expr) => {
        /// Circuit to verify the rsa signature for the given hash and public key.
        #[derive(Debug, Clone)]
        pub struct $circuit_name<F: PrimeField> {
            /// The hash of the message to be verified.
            pub hash_bytes: Vec<u8>,
            /// The public key to be verified.
            pub public_key_n: BigUint,
            /// The signature to be verified.
            pub signature: BigUint,
            _f: PhantomData<F>,
        }

        #[derive(Debug, Clone)]
        pub struct SignVerifyInstanceConfig<F: PrimeField> {
            inner: SignVerifyConfig<F>,
            instance: Column<Instance>,
        }

        impl<F: PrimeField> Circuit<F> for $circuit_name<F> {
            type Config = SignVerifyInstanceConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self {
                    hash_bytes: vec![0; self.hash_bytes.len()],
                    public_key_n: self.public_key_n.clone(),
                    signature: self.signature.clone(),
                    _f: PhantomData,
                }
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                // let config_params = read_default_circuit_config_params();
                let range_config = RangeConfig::configure(
                    meta,
                    halo2_base::gates::range::RangeStrategy::Vertical,
                    &[$num_flex_advice],
                    &[$num_range_lookup_advice],
                    $num_flex_advice,
                    $range_lookup_bits,
                    0,
                    $degree as usize,
                );
                let inner = SignVerifyConfig::configure(range_config, $public_key_bits);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                SignVerifyInstanceConfig { inner, instance }
            }

            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
                config.inner.range().load_lookup_table(&mut layouter)?;
                let mut first_pass = SKIP_FIRST_PASS;
                let mut public_hash_cell = vec![];
                // let config_params = read_default_circuit_config_params();
                // let sign_verify_params = config_params.sign_verify_config.unwrap();
                assert_eq!(self.public_key_n.bits() as usize, $public_key_bits);
                layouter.assign_region(
                    || "sign verify",
                    |region| {
                        if first_pass {
                            first_pass = false;
                            return Ok(());
                        }
                        let ctx = &mut config.inner.rsa_config.new_context(region);
                        let range = config.inner.range();
                        let gate = range.gate();
                        let poseidon = PoseidonChipBn254_8_58::new(ctx, gate);
                        let assigned_hash_bytes = self
                            .hash_bytes
                            .iter()
                            .map(|byte| gate.load_witness(ctx, Value::known(F::from(*byte as u64))))
                            .collect_vec();
                        let result = config
                            .inner
                            .verify_signature(ctx, &assigned_hash_bytes, self.public_key_n.clone(), self.signature.clone())?;
                        let assigned_public_key = result.assigned_public_key;
                        let assigned_signature = result.assigned_signature;

                        let sign_rand = poseidon.hash_elements(ctx, gate, &assigned_signature.c.limbs()).unwrap().0[0].clone();
                        let mut public_key_n_hash_input = vec![];
                        let hide_public_key: bool = $hide_public_key;
                        if hide_public_key {
                            public_key_n_hash_input.push(sign_rand);
                        }
                        public_key_n_hash_input.append(&mut assigned_public_key.n.limbs().to_vec());
                        let public_key_n_hash = poseidon.hash_elements(ctx, gate, &public_key_n_hash_input).unwrap().0[0].clone();
                        let hash_commit = assigned_commit_wtns_bytes(ctx, gate, &poseidon, &public_key_n_hash_input[0], &assigned_hash_bytes);
                        range.finalize(ctx);
                        public_hash_cell.push(public_key_n_hash.cell());
                        public_hash_cell.push(hash_commit.cell());
                        Ok(())
                    },
                )?;
                for (idx, cell) in public_hash_cell.iter().enumerate() {
                    layouter.constrain_instance(*cell, config.instance, idx)?;
                }
                Ok(())
            }
        }

        impl<F: PrimeField> CircuitExt<F> for $circuit_name<F> {
            fn num_instance(&self) -> Vec<usize> {
                vec![2]
            }

            fn instances(&self) -> Vec<Vec<F>> {
                // let config_params = read_default_circuit_config_params();
                // let sign_verify_params = config_params.sign_verify_config.unwrap();
                let limb_bits = SignVerifyConfig::<F>::LIMB_BITS;
                let sign_rand = derive_sign_rand(&self.signature, $public_key_bits, limb_bits);
                let mut public_key_n_hash_input = vec![];
                let hide_public_key: bool = $hide_public_key;
                if hide_public_key {
                    public_key_n_hash_input.push(sign_rand);
                }
                let num_limbs = $public_key_bits / limb_bits;
                let public_key_n_limbs = decompose_biguint(&self.public_key_n, num_limbs, $public_key_bits);
                public_key_n_hash_input.append(&mut public_key_n_limbs.to_vec());
                let public_key_n_hash = poseidon_hash_fields(&public_key_n_hash_input);
                let hash_commit = value_commit_wtns_bytes(&sign_rand, &self.hash_bytes);
                vec![vec![public_key_n_hash, hash_commit]]
            }
        }

        impl<F: PrimeField> $circuit_name<F> {
            pub fn new(hash_bytes: Vec<u8>, public_key_n: BigUint, signature: BigUint) -> Self {
                Self {
                    hash_bytes,
                    public_key_n,
                    signature,
                    _f: PhantomData,
                }
            }
        }
    };
}

pub fn derive_sign_rand<F: PrimeField>(signature: &BigUint, public_key_bits: usize, limb_size: usize) -> F {
    let num_limbs = public_key_bits / limb_size;
    let limbs = decompose_biguint(signature, num_limbs, public_key_bits);
    poseidon_hash_fields(&limbs)
}

impl_sign_verify_circuit!(DummySignVerifyCircuit, 1, 1, 8, 5, 2048, false);
