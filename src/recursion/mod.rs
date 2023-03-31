use crate::impl_email_verify_circuit;
use halo2_base::halo2_proofs;
use halo2_base::halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::{gates::range::RangeConfig, utils::PrimeField, Context};
use halo2_dynamic_sha256::Field;
use halo2_regex::defs::{AllstrRegexDef, SubstrRegexDef};
use halo2_rsa::{RSAPublicKey, RSASignature};
use rand::rngs::OsRng;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_proof_shplonk, gen_snark_shplonk},
    CircuitExt, Snark,
};

use halo2_base::halo2_proofs::{
    circuit::{floor_planner::V1, Cell, Value},
    dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
    plonk::{Any, Column, Instance, ProvingKey, VerifyingKey},
};
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
// use mail_auth::{dkim::{self, Canonicalization}, common::{headers::Writable, verify::VerifySignature}, AuthenticatedMessage, Resolver, DkimResult};
use num_bigint::BigUint;
// use mail_auth::{common::{crypto::{RsaKey},headers::HeaderWriter},dkim::DkimSigner};
// use mail_parser::{decoders::base64::base64_decode,  Message, Addr, HeaderValue};
use crate::EmailVerifyConfig;
use rand::Rng;

#[macro_export]
macro_rules! impl_aggregation_email_verify {
    ($app_config_name:ident, $app_circuit_name:ident, $gen_app_pk:ident, $gen_app_snark:ident, $gen_pk_of_agg:ident, $gen_proof_of_agg:ident, $k:expr) => {
        pub fn $gen_app_pk(
            params: &ParamsKZG<Bn256>,
            circuit: $app_circuit_name<Fr>,
        ) -> ProvingKey<G1Affine> {
            gen_pk(params, &circuit, None)
        }

        pub fn $gen_app_snark(
            params: &ParamsKZG<Bn256>,
            circuit: $app_circuit_name<Fr>,
            pk: &ProvingKey<G1Affine>,
        ) -> Snark {
            gen_snark_shplonk(params, pk, circuit, &mut OsRng, None::<&str>)
        }

        pub fn $gen_pk_of_agg(
            params: &ParamsKZG<Bn256>,
            snarks: impl IntoIterator<Item = Snark>,
            rng: impl Rng + Send,
        ) -> ProvingKey<G1Affine> {
            let agg_circuit = AggregationCircuit::new(params, snarks, rng);
            gen_pk(params, &agg_circuit, None)
        }

        pub fn $gen_proof_of_agg(
            params: &ParamsKZG<Bn256>,
            pk: &ProvingKey<G1Affine>,
            snarks: impl IntoIterator<Item = Snark>,
            rng: &mut (impl Rng + Send + Clone),
        ) -> Vec<u8> {
            let agg_circuit = AggregationCircuit::new(params, snarks, rng.clone());
            let instances = agg_circuit.instances();
            gen_proof_shplonk(params, pk, agg_circuit.clone(), instances, rng, None)
        }
    };
}
