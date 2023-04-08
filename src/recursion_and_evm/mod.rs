use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs;
use halo2_base::halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::poly::{commitment::Params, kzg::commitment::ParamsKZG};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::{gates::range::RangeConfig, utils::PrimeField, Context};
use halo2_dynamic_sha256::Field;
use halo2_regex::defs::{AllstrRegexDef, SubstrRegexDef};
use halo2_rsa::{RSAPublicKey, RSASignature};
use num_traits::Pow;
use rand::rngs::OsRng;
use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_gwc, gen_evm_verifier_gwc};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::PublicAggregationCircuit, gen_snark_gwc},
    CircuitExt, Snark, LIMBS,
};
use std::env::set_var;

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

pub fn gen_app_proving_key<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    circuit: &C,
) -> ProvingKey<G1Affine> {
    gen_pk(params, circuit, None)
}

pub fn gen_snark<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    circuit: C,
    pk: &ProvingKey<G1Affine>,
) -> Snark {
    gen_snark_gwc(params, pk, circuit, &mut OsRng, None::<&str>)
}

// pub fn gen_aggregation_proving_key(
//     params: &ParamsKZG<Bn256>,
//     snarks: Vec<Snark>,
//     config_filepath: &str,
//     has_prev_accumulator: bool,
// ) -> ProvingKey<G1Affine> {
//     set_var("VERIFY_CONFIG", config_filepath);
//     let agg_circuit =
//         PublicAggregationCircuit::new(params, snarks, has_prev_accumulator, &mut OsRng);
//     gen_pk(params, &agg_circuit, None)
// }

pub fn gen_aggregation_snark(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    snarks: Vec<Snark>,
    config_filepath: &str,
    has_prev_accumulator: bool,
) -> Snark {
    set_var("VERIFY_CONFIG", config_filepath);
    let agg_circuit =
        PublicAggregationCircuit::new(params, snarks, has_prev_accumulator, &mut OsRng);
    gen_snark(params, agg_circuit.clone(), pk)
}

pub fn compute_agg_num_instances(app_num_instances: &[usize], log2_proofs: u32) -> Vec<usize> {
    debug_assert!(log2_proofs > 0);
    let num_instances_per_app = app_num_instances.iter().sum::<usize>();
    vec![4 * LIMBS + num_instances_per_app * 2usize.pow(log2_proofs)]
}

pub fn gen_multi_layer_proving_keys<C: CircuitExt<Fr> + Clone>(
    app_params: &ParamsKZG<Bn256>,
    app_to_agg_params: Option<&ParamsKZG<Bn256>>,
    agg_to_agg_params: Option<&ParamsKZG<Bn256>>,
    app_to_agg_config_path: &str,
    agg_to_agg_config_path: &str,
    circuit: &C,
    log2_proofs: u32,
) -> (Vec<ProvingKey<G1Affine>>, Vec<usize>) {
    let mut pks = vec![];
    debug_assert!(
        log2_proofs < 1 || app_to_agg_params.is_some(),
        "app_to_agg_params is not null when log2_proofs >= 1."
    );
    debug_assert!(
        log2_proofs < 2 || agg_to_agg_params.is_some(),
        "agg_to_agg_params is not null when log2_proofs >= 2."
    );
    // let app_params = {
    //     let mut params = params.clone();
    //     params.downsize(app_k);
    //     params
    // };
    // let app_to_agg_params = {
    //     let mut params = params.clone();
    //     params.downsize(app_to_agg_k);
    //     params
    // };
    let mock = start_timer!(|| "app pk generation");
    let app_pk = gen_app_proving_key(app_params, circuit);
    end_timer!(mock);
    pks.push(app_pk);
    let mut last_circuit = None;

    for idx in 1..(log2_proofs + 1) {
        if idx == 1 {
            let snarks = (0..2)
                .map(|_| gen_snark(app_params, circuit.clone(), &pks[0]))
                .collect::<Vec<Snark>>();
            set_var("VERIFY_CONFIG", app_to_agg_config_path);
            let new_circuit = PublicAggregationCircuit::new(
                &app_to_agg_params.unwrap(),
                snarks,
                false,
                &mut OsRng,
            );
            let mock = start_timer!(|| "app_to_agg pk generation");
            let app_to_agg_pk = gen_pk(app_to_agg_params.unwrap(), &new_circuit, None);
            end_timer!(mock);
            pks.push(app_to_agg_pk);
            last_circuit = Some(new_circuit);
        } else {
            let snarks = (0..2)
                .map(|_| {
                    gen_snark(
                        agg_to_agg_params.unwrap(),
                        last_circuit.as_ref().unwrap().clone(),
                        &pks[idx as usize - 1],
                    )
                })
                .collect::<Vec<Snark>>();
            set_var("VERIFY_CONFIG", agg_to_agg_config_path);
            let new_circuit =
                PublicAggregationCircuit::new(agg_to_agg_params.unwrap(), snarks, true, &mut OsRng);
            let mock = start_timer!(|| "agg_to_agg pk generation");
            let agg_to_agg_pk = gen_pk(agg_to_agg_params.unwrap(), &new_circuit, None);
            end_timer!(mock);
            pks.push(agg_to_agg_pk);
            last_circuit = Some(new_circuit);
        }
    }
    let num_instances = match last_circuit {
        Some(c) => c.num_instance(),
        None => circuit.num_instance(),
    };
    (pks, num_instances)
}

pub fn gen_multi_layer_evm_verifier<C: CircuitExt<Fr> + Clone>(
    params: &ParamsKZG<Bn256>,
    last_vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    log2_proofs: u32,
) -> Vec<u8> {
    if log2_proofs == 0 {
        gen_evm_verifier_gwc::<C>(params, &last_vk, num_instance, None)
    } else if log2_proofs == 1 {
        gen_evm_verifier_gwc::<PublicAggregationCircuit>(params, &last_vk, num_instance, None)
    } else {
        gen_evm_verifier_gwc::<PublicAggregationCircuit>(params, &last_vk, num_instance, None)
    }
}

/// Reutrn (proof bytes, accumulater values in the instance column)
pub fn prove_multi_layer_evm<C: CircuitExt<Fr> + Clone>(
    app_params: &ParamsKZG<Bn256>,
    app_to_agg_params: Option<&ParamsKZG<Bn256>>,
    agg_to_agg_params: Option<&ParamsKZG<Bn256>>,
    app_to_agg_config_path: &str,
    agg_to_agg_config_path: &str,
    circuits: &[C],
    pks: &[ProvingKey<G1Affine>],
    log2_proofs: u32,
) -> (Vec<u8>, Vec<Fr>) {
    let mut n_proof = circuits.len();
    debug_assert_eq!(2usize.pow(log2_proofs), n_proof);
    debug_assert!(
        log2_proofs < 1 || app_to_agg_params.is_some(),
        "app_to_agg_params is not null when log2_proofs >= 1."
    );
    debug_assert!(
        log2_proofs < 2 || agg_to_agg_params.is_some(),
        "agg_to_agg_params is not null when log2_proofs >= 2."
    );
    // let app_params = {
    //     let mut params = params.clone();
    //     params.downsize(app_k);
    //     params
    // };
    // let app_to_agg_params = {
    //     let mut params = params.clone();
    //     params.downsize(app_to_agg_k);
    //     params
    // };
    if log2_proofs == 0 {
        let instances = circuits[0].instances();
        let mock = start_timer!(|| format!("{} app evm proof generation", n_proof));
        let evm_proof = gen_evm_proof_gwc(
            app_params,
            &pks[0],
            circuits[0].clone(),
            instances.clone(),
            &mut OsRng,
        );
        end_timer!(mock);
        return (evm_proof, vec![]);
    }
    let mock = start_timer!(|| format!("{} app snarks generation", n_proof));
    let app_snarks = (0..n_proof)
        .map(|i| gen_snark(app_params, circuits[i].clone(), &pks[0]))
        .collect::<Vec<Snark>>();
    end_timer!(mock);
    n_proof = n_proof >> 1;
    if log2_proofs == 1 {
        let circuit = PublicAggregationCircuit::new(
            &app_to_agg_params.unwrap(),
            app_snarks,
            false,
            &mut OsRng,
        );
        let instances = circuit.instances();
        let mock = start_timer!(|| format!("{} app_to_agg evm proof generation", n_proof));
        let evm_proof = gen_evm_proof_gwc(
            app_to_agg_params.unwrap(),
            &pks[1],
            circuit,
            instances.clone(),
            &mut OsRng,
        );
        end_timer!(mock);
        return (evm_proof, instances[0][0..4 * LIMBS].to_vec());
    }
    let mut agg_snarks = (0..n_proof)
        .map(|idx| {
            let mock = start_timer!(|| "app_to_agg snarks generation");
            let snark = gen_aggregation_snark(
                app_to_agg_params.unwrap(),
                &pks[1],
                vec![app_snarks[2 * idx].clone(), app_snarks[2 * idx + 1].clone()],
                app_to_agg_config_path,
                false,
            );
            end_timer!(mock);
            snark
        })
        .collect::<Vec<Snark>>();
    n_proof = n_proof >> 1;
    let mut pk_idx = 2;
    while n_proof > 1 {
        for idx in 0..n_proof {
            let mock = start_timer!(|| "agg_to_agg snarks generation");
            agg_snarks[idx] = gen_aggregation_snark(
                agg_to_agg_params.unwrap(),
                &pks[pk_idx],
                vec![agg_snarks[2 * idx].clone(), agg_snarks[2 * idx + 1].clone()],
                agg_to_agg_config_path,
                true,
            );
            end_timer!(mock);
        }
        agg_snarks.drain(n_proof..);
        pk_idx += 1;
        n_proof = n_proof >> 1;
    }
    {
        let circuit = PublicAggregationCircuit::new(
            agg_to_agg_params.unwrap(),
            vec![agg_snarks[0].clone(), agg_snarks[1].clone()],
            true,
            &mut OsRng,
        );
        let instances = circuit.instances();
        let mock = start_timer!(|| format!("{} agg_to_agg evm proof generation", n_proof));
        let evm_proof = gen_evm_proof_gwc(
            agg_to_agg_params.unwrap(),
            &pks[pk_idx],
            circuit,
            instances.clone(),
            &mut OsRng,
        );
        end_timer!(mock);
        (evm_proof, instances[0][0..4 * LIMBS].to_vec())
    }
}

// pub fn evm_verify_multi_layer(verifier_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
//     evm_verify(verifier_code, instances, proof)
// }
