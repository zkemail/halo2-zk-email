pub mod poseidon_circuit;
use self::poseidon_circuit::{poseidon_hash_fields, HasherChip, PoseidonChipBn254_8_58};
use halo2_base::halo2_proofs::{arithmetic::FieldExt, plonk::*};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    AssignedValue, Context, QuantumCell,
};

pub fn value_commit_wtns_bytes<F: FieldExt>(rand: &F, wtns_bytes: &[u8]) -> F {
    let inputs = vec![vec![rand.clone()], value_bytes2fields(wtns_bytes)].concat();
    poseidon_hash_fields(&inputs)
}

pub fn value_bytes2fields<F: FieldExt>(wtns_bytes: &[u8]) -> Vec<F> {
    let byte_len = wtns_bytes.len();
    let remaining_bytes = byte_len % 31;
    let num_limbs = if remaining_bytes == 0 { byte_len / 31 } else { byte_len / 31 + 1 };

    let mut inputs = vec![];
    for idx in 0..num_limbs {
        let mut sum = F::zero();
        let mut coeff = F::one();
        if idx == num_limbs - 1 && remaining_bytes != 0 {
            for j in 0..remaining_bytes {
                sum += F::from(wtns_bytes[idx * 31 + j] as u64) * coeff;
                coeff *= F::from(256u64);
            }
        } else {
            for j in 0..31 {
                sum += F::from(wtns_bytes[idx * 31 + j] as u64) * coeff;
                coeff *= F::from(256u64);
            }
        }
        inputs.push(sum);
    }
    inputs
}

pub fn assigned_bytes2fields<'v: 'a, 'a, F: FieldExt>(ctx: &mut Context<'v, F>, gate: &FlexGateConfig<F>, wtns_bytes: &'a [AssignedValue<F>]) -> Vec<AssignedValue<'a, F>> {
    let byte_len = wtns_bytes.len();
    let remaining_bytes = byte_len % 31;
    let num_limbs = if remaining_bytes == 0 { byte_len / 31 } else { byte_len / 31 + 1 };
    let mut inputs = vec![];
    for idx in 0..num_limbs {
        let mut sum = gate.load_zero(ctx);
        let mut coeff = F::one();
        if idx == num_limbs - 1 && remaining_bytes != 0 {
            for j in 0..remaining_bytes {
                sum = gate.mul_add(
                    ctx,
                    QuantumCell::Existing(&wtns_bytes[idx * 31 + j]),
                    QuantumCell::Constant(coeff),
                    QuantumCell::Existing(&sum),
                );
                coeff *= F::from(256u64);
            }
        } else {
            for j in 0..31 {
                sum = gate.mul_add(
                    ctx,
                    QuantumCell::Existing(&wtns_bytes[idx * 31 + j]),
                    QuantumCell::Constant(coeff),
                    QuantumCell::Existing(&sum),
                );
                coeff *= F::from(256u64);
            }
        }
        inputs.push(sum);
    }
    inputs
}

pub fn assigned_commit_wtns_bytes<'v: 'a, 'a, F: FieldExt>(
    ctx: &mut Context<'v, F>,
    gate: &FlexGateConfig<F>,
    poseidon: &'a PoseidonChipBn254_8_58<F>,
    rand: &'a AssignedValue<F>,
    wtns_bytes: &'a [AssignedValue<F>],
) -> AssignedValue<'a, F> {
    let inputs = vec![vec![rand.clone()], assigned_bytes2fields(ctx, gate, wtns_bytes)].concat();
    let result = poseidon.hash_elements(ctx, gate, &inputs).unwrap().0;
    result[0].clone()
}
