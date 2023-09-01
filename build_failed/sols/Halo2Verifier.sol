pragma solidity ^0.8.21;

contract Halo2Verifier {
    uint256 internal constant PROOF_LEN_CPTR = 0x64;
    uint256 internal constant PROOF_CPTR = 0x84;
    uint256 internal constant NUM_INSTANCE_CPTR = 0x45a4;
    uint256 internal constant INSTANCE_CPTR = 0x45c4;

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x1b44;
    uint256 internal constant LAST_QUOTIENT_X_CPTR = 0x1c44;

    uint256 internal constant VK_MPTR = 0x28c0;
    uint256 internal constant VK_DIGEST_MPTR = 0x28c0;
    uint256 internal constant K_MPTR = 0x28e0;
    uint256 internal constant N_INV_MPTR = 0x2900;
    uint256 internal constant OMEGA_MPTR = 0x2920;
    uint256 internal constant OMEGA_INV_MPTR = 0x2940;
    uint256 internal constant OMEGA_INV_TO_L_MPTR = 0x2960;
    uint256 internal constant NUM_INSTANCES_MPTR = 0x2980;
    uint256 internal constant HAS_ACCUMULATOR_MPTR = 0x29a0;
    uint256 internal constant ACC_OFFSET_MPTR = 0x29c0;
    uint256 internal constant NUM_ACC_LIMBS_MPTR = 0x29e0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x2a00;
    uint256 internal constant G1_X_MPTR = 0x2a20;
    uint256 internal constant G1_Y_MPTR = 0x2a40;
    uint256 internal constant G2_X_1_MPTR = 0x2a60;
    uint256 internal constant G2_X_2_MPTR = 0x2a80;
    uint256 internal constant G2_Y_1_MPTR = 0x2aa0;
    uint256 internal constant G2_Y_2_MPTR = 0x2ac0;
    uint256 internal constant NEG_S_G2_X_1_MPTR = 0x2ae0;
    uint256 internal constant NEG_S_G2_X_2_MPTR = 0x2b00;
    uint256 internal constant NEG_S_G2_Y_1_MPTR = 0x2b20;
    uint256 internal constant NEG_S_G2_Y_2_MPTR = 0x2b40;

    uint256 internal constant CHALLENGE_MPTR = 0x4820;

    uint256 internal constant THETA_MPTR = 0x4820;
    uint256 internal constant BETA_MPTR = 0x4840;
    uint256 internal constant GAMMA_MPTR = 0x4860;
    uint256 internal constant Y_MPTR = 0x4880;
    uint256 internal constant X_MPTR = 0x48a0;
    uint256 internal constant ZETA_MPTR = 0x48c0;
    uint256 internal constant NU_MPTR = 0x48e0;
    uint256 internal constant MU_MPTR = 0x4900;

    uint256 internal constant INSTANCE_EVAL_MPTR = 0x4920;
    uint256 internal constant X_N_MPTR = 0x4940;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x4960;
    uint256 internal constant L_LAST_MPTR = 0x4980;
    uint256 internal constant L_BLIND_MPTR = 0x49a0;
    uint256 internal constant L_0_MPTR = 0x49c0;
    uint256 internal constant QUOTIENT_EVAL_MPTR = 0x49e0;
    uint256 internal constant QUOTIENT_X_MPTR = 0x4a00;
    uint256 internal constant QUOTIENT_Y_MPTR = 0x4a20;
    uint256 internal constant R_EVAL_MPTR = 0x4a40;
    uint256 internal constant PAIRING_LHS_X_MPTR = 0x4a60;
    uint256 internal constant PAIRING_LHS_Y_MPTR = 0x4a80;
    uint256 internal constant PAIRING_RHS_X_MPTR = 0x4aa0;
    uint256 internal constant PAIRING_RHS_Y_MPTR = 0x4ac0;
    uint256 internal constant ACC_LHS_X_MPTR = 0x4ae0;
    uint256 internal constant ACC_LHS_Y_MPTR = 0x4b00;
    uint256 internal constant ACC_RHS_X_MPTR = 0x4b20;
    uint256 internal constant ACC_RHS_Y_MPTR = 0x4b40;

    function verifyProof(
        address vk,
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q)
                -> ret0, ret1, ret2
            {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(
                    ret0,
                    eq(
                        mulmod(y, y, q),
                        addmod(mulmod(x, mulmod(x, x, q), q), 3, q)
                    )
                )
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r)
                -> ret0, ret1
            {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[0..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_end, r) -> ret {
                let mptr := 0x20
                let gp_mptr := mptr_end
                let gp := mload(0x00)
                for {

                } lt(mptr, sub(mptr_end, 0x20)) {

                } {
                    gp := mulmod(gp, mload(mptr), r)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), r)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(r, 2))
                mstore(add(gp_mptr, 0xa0), r)
                ret := and(
                    success,
                    staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20)
                )
                let all_inv := mload(gp_mptr)

                gp_mptr := sub(gp_mptr, 0x20)
                for {

                } lt(0x20, mptr) {

                } {
                    let inv := mulmod(all_inv, mload(gp_mptr), r)
                    all_inv := mulmod(all_inv, mload(mptr), r)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(0x20), r)
                let inv_second := mulmod(all_inv, mload(0x00), r)
                mstore(0x00, inv_first)
                mstore(0x20, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(
                    success,
                    staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40)
                )
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(
                    success,
                    staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40)
                )
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(
                    success,
                    staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40)
                )
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(
                    success,
                    staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40)
                )
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(
                    success,
                    staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20)
                )
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let
                q
            := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let
                r
            := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field

            // Initialize success as true
            let success := true

            {
                // Copy vk into memory
                extcodecopy(vk, VK_MPTR, 0x00, 0x1f60)

                // Check valid length of proof
                success := and(
                    success,
                    eq(0x4520, calldataload(PROOF_LEN_CPTR))
                )

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(
                    success,
                    eq(num_instances, calldataload(NUM_INSTANCE_CPTR))
                )

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := INSTANCE_CPTR
                for {
                    let instance_cptr_end := add(
                        instance_cptr,
                        mul(0x20, num_instances)
                    )
                } lt(instance_cptr, instance_cptr_end) {

                } {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := PROOF_CPTR
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for {
                    let proof_cptr_end := add(proof_cptr, 0x09c0)
                } lt(proof_cptr, proof_cptr_end) {

                } {
                    success, proof_cptr, hash_mptr := read_ec_point(
                        success,
                        proof_cptr,
                        hash_mptr,
                        q
                    )
                }

                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                )

                // Phase 2
                for {
                    let proof_cptr_end := add(proof_cptr, 0x0900)
                } lt(proof_cptr, proof_cptr_end) {

                } {
                    success, proof_cptr, hash_mptr := read_ec_point(
                        success,
                        proof_cptr,
                        hash_mptr,
                        q
                    )
                }

                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                )
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for {
                    let proof_cptr_end := add(proof_cptr, 0x0800)
                } lt(proof_cptr, proof_cptr_end) {

                } {
                    success, proof_cptr, hash_mptr := read_ec_point(
                        success,
                        proof_cptr,
                        hash_mptr,
                        q
                    )
                }

                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                )

                // Phase 4
                for {
                    let proof_cptr_end := add(proof_cptr, 0x0140)
                } lt(proof_cptr, proof_cptr_end) {

                } {
                    success, proof_cptr, hash_mptr := read_ec_point(
                        success,
                        proof_cptr,
                        hash_mptr,
                        q
                    )
                }

                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                )

                // Read evaluations
                for {
                    let proof_cptr_end := add(proof_cptr, 0x28a0)
                } lt(proof_cptr, proof_cptr_end) {

                } {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                ) // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r) // nu

                success, proof_cptr, hash_mptr := read_ec_point(
                    success,
                    proof_cptr,
                    hash_mptr,
                    q
                ) // W

                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                ) // mu

                success, proof_cptr, hash_mptr := read_ec_point(
                    success,
                    proof_cptr,
                    hash_mptr,
                    q
                ) // W'

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                //     let cptr := add(
                //         INSTANCE_CPTR,
                //         mul(mload(ACC_OFFSET_MPTR), 0x20)
                //     )
                //     let lhs_y_off := mul(num_limbs, 0x20)
                //     let rhs_x_off := mul(lhs_y_off, 2)
                //     let rhs_y_off := mul(lhs_y_off, 3)
                //     let lhs_x := calldataload(cptr)
                //     let lhs_y := calldataload(add(cptr, lhs_y_off))
                //     let rhs_x := calldataload(add(cptr, rhs_x_off))
                //     let rhs_y := calldataload(add(cptr, rhs_y_off))
                //     for {
                //         let cptr_end := add(cptr, mul(0x20, num_limbs))
                //         let shift := num_limb_bits
                //     } lt(cptr, cptr_end) {

                //     } {
                //         cptr := add(cptr, 0x20)
                //         lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                //         lhs_y := add(
                //             lhs_y,
                //             shl(shift, calldataload(add(cptr, lhs_y_off)))
                //         )
                //         rhs_x := add(
                //             rhs_x,
                //             shl(shift, calldataload(add(cptr, rhs_x_off)))
                //         )
                //         rhs_y := add(
                //             rhs_y,
                //             shl(shift, calldataload(add(cptr, rhs_y_off)))
                //         )
                //         shift := add(shift, num_limb_bits)
                //     }

                //     success := and(
                //         success,
                //         eq(
                //             mulmod(lhs_y, lhs_y, q),
                //             addmod(
                //                 mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q),
                //                 3,
                //                 q
                //             )
                //         )
                //     )
                //     success := and(
                //         success,
                //         eq(
                //             mulmod(rhs_y, rhs_y, q),
                //             addmod(
                //                 mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q),
                //                 3,
                //                 q
                //             )
                //         )
                //     )

                //     mstore(ACC_LHS_X_MPTR, lhs_x)
                //     mstore(ACC_LHS_Y_MPTR, lhs_y)
                //     mstore(ACC_RHS_X_MPTR, rhs_x)
                //     mstore(ACC_RHS_Y_MPTR, rhs_y)
                // }

                // pop(q)
            }

            // // Revert earlier if anything from calldata is invalid
            // if iszero(success) {
            //     revert(0, 0)
            // }

            // // Compute lagrange evaluations and instance evaluation
            // {
            //     let k := mload(K_MPTR)
            //     let x := mload(X_MPTR)
            //     let x_n := x
            //     for {
            //         let idx := 0
            //     } lt(idx, k) {
            //         idx := add(idx, 1)
            //     } {
            //         x_n := mulmod(x_n, x_n, r)
            //     }
            //     mstore(X_N_MPTR, x_n)

            //     let omega := mload(OMEGA_MPTR)

            //     let mptr_end := mul(0x20, add(mload(NUM_INSTANCES_MPTR), 7))
            //     let mptr := 0x00
            //     for {
            //         let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR)
            //     } lt(mptr, mptr_end) {
            //         mptr := add(mptr, 0x20)
            //     } {
            //         mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
            //         pow_of_omega := mulmod(pow_of_omega, omega, r)
            //     }
            //     let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
            //     mstore(mptr, x_n_minus_1)
            //     success := batch_invert(success, add(mptr, 0x20), r)
            //     mstore(X_N_MINUS_1_INV_MPTR, mload(mptr))

            //     mptr := 0x00
            //     let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
            //     for {
            //         let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR)
            //     } lt(mptr, mptr_end) {
            //         mptr := add(mptr, 0x20)
            //     } {
            //         mstore(
            //             mptr,
            //             mulmod(
            //                 l_i_common,
            //                 mulmod(mload(mptr), pow_of_omega, r),
            //                 r
            //             )
            //         )
            //         pow_of_omega := mulmod(pow_of_omega, omega, r)
            //     }

            //     let l_i_cptr := 0x0100
            //     let instance_cptr := add(INSTANCE_CPTR, 0x20)
            //     let instance_eval := mulmod(
            //         mload(0xe0),
            //         calldataload(INSTANCE_CPTR),
            //         r
            //     )
            //     for {
            //         let instance_cptr_end := add(
            //             INSTANCE_CPTR,
            //             mul(0x20, mload(NUM_INSTANCES_MPTR))
            //         )
            //     } lt(instance_cptr, instance_cptr_end) {

            //     } {
            //         instance_eval := addmod(
            //             instance_eval,
            //             mulmod(mload(l_i_cptr), calldataload(instance_cptr), r),
            //             r
            //         )
            //         l_i_cptr := add(l_i_cptr, 0x20)
            //         instance_cptr := add(instance_cptr, 0x20)
            //     }

            //     l_i_cptr := 0x40
            //     let l_blind := mload(0x20)
            //     for {
            //         let l_i_cptr_end := 224
            //     } lt(l_i_cptr, l_i_cptr_end) {

            //     } {
            //         l_blind := addmod(l_blind, mload(l_i_cptr), r)
            //         l_i_cptr := add(l_i_cptr, 0x20)
            //     }

            //     mstore(INSTANCE_EVAL_MPTR, instance_eval)
            //     mstore(L_LAST_MPTR, mload(0x00))
            //     mstore(L_BLIND_MPTR, l_blind)
            //     mstore(L_0_MPTR, mload(0xe0))
            // }

            // // Compute quotient evavluation
            // {
            //     let quotient_eval_numer
            //     let
            //         delta
            //     := 4131629893567559867359510883348571134090853742863529169391034518566172092834
            //     let y := mload(Y_MPTR)
            //     {
            //         let f_55 := calldataload(0x2d84)
            //         let a_0 := calldataload(0x1c84)
            //         let a_0_next_1 := calldataload(0x1ca4)
            //         let a_0_next_2 := calldataload(0x1cc4)
            //         let var0 := mulmod(a_0_next_1, a_0_next_2, r)
            //         let var1 := addmod(a_0, var0, r)
            //         let a_0_next_3 := calldataload(0x1ce4)
            //         let var2 := sub(r, a_0_next_3)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(f_55, var3, r)
            //         quotient_eval_numer := var4
            //     }
            //     {
            //         let f_56 := calldataload(0x2da4)
            //         let a_1 := calldataload(0x1d04)
            //         let a_1_next_1 := calldataload(0x1d24)
            //         let a_1_next_2 := calldataload(0x1d44)
            //         let var0 := mulmod(a_1_next_1, a_1_next_2, r)
            //         let var1 := addmod(a_1, var0, r)
            //         let a_1_next_3 := calldataload(0x1d64)
            //         let var2 := sub(r, a_1_next_3)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(f_56, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_57 := calldataload(0x2dc4)
            //         let a_2 := calldataload(0x1d84)
            //         let a_2_next_1 := calldataload(0x1da4)
            //         let a_2_next_2 := calldataload(0x1dc4)
            //         let var0 := mulmod(a_2_next_1, a_2_next_2, r)
            //         let var1 := addmod(a_2, var0, r)
            //         let a_2_next_3 := calldataload(0x1de4)
            //         let var2 := sub(r, a_2_next_3)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(f_57, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_58 := calldataload(0x2de4)
            //         let a_3 := calldataload(0x1e04)
            //         let a_3_next_1 := calldataload(0x1e24)
            //         let a_3_next_2 := calldataload(0x1e44)
            //         let var0 := mulmod(a_3_next_1, a_3_next_2, r)
            //         let var1 := addmod(a_3, var0, r)
            //         let a_3_next_3 := calldataload(0x1e64)
            //         let var2 := sub(r, a_3_next_3)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(f_58, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_59 := calldataload(0x2e04)
            //         let a_4 := calldataload(0x1e84)
            //         let a_4_next_1 := calldataload(0x1ea4)
            //         let a_4_next_2 := calldataload(0x1ec4)
            //         let var0 := mulmod(a_4_next_1, a_4_next_2, r)
            //         let var1 := addmod(a_4, var0, r)
            //         let a_4_next_3 := calldataload(0x1ee4)
            //         let var2 := sub(r, a_4_next_3)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(f_59, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_60 := calldataload(0x2e24)
            //         let a_5 := calldataload(0x1f04)
            //         let a_5_next_1 := calldataload(0x1f24)
            //         let a_5_next_2 := calldataload(0x1f44)
            //         let var0 := mulmod(a_5_next_1, a_5_next_2, r)
            //         let var1 := addmod(a_5, var0, r)
            //         let a_5_next_3 := calldataload(0x1f64)
            //         let var2 := sub(r, a_5_next_3)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(f_60, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_61 := calldataload(0x2e44)
            //         let a_6 := calldataload(0x1f84)
            //         let a_6_next_1 := calldataload(0x1fa4)
            //         let a_6_next_2 := calldataload(0x1fc4)
            //         let var0 := mulmod(a_6_next_1, a_6_next_2, r)
            //         let var1 := addmod(a_6, var0, r)
            //         let a_6_next_3 := calldataload(0x1fe4)
            //         let var2 := sub(r, a_6_next_3)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(f_61, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_62 := calldataload(0x2e64)
            //         let a_7 := calldataload(0x2004)
            //         let a_7_next_1 := calldataload(0x2024)
            //         let a_7_next_2 := calldataload(0x2044)
            //         let var0 := mulmod(a_7_next_1, a_7_next_2, r)
            //         let var1 := addmod(a_7, var0, r)
            //         let a_7_next_3 := calldataload(0x2064)
            //         let var2 := sub(r, a_7_next_3)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(f_62, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_63 := calldataload(0x2e84)
            //         let a_8 := calldataload(0x2084)
            //         let a_8_next_1 := calldataload(0x20a4)
            //         let a_8_next_2 := calldataload(0x20c4)
            //         let var0 := mulmod(a_8_next_1, a_8_next_2, r)
            //         let var1 := addmod(a_8, var0, r)
            //         let a_8_next_3 := calldataload(0x20e4)
            //         let var2 := sub(r, a_8_next_3)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(f_63, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_64 := calldataload(0x2ea4)
            //         let a_9 := calldataload(0x2104)
            //         let a_9_next_1 := calldataload(0x2124)
            //         let a_9_next_2 := calldataload(0x2144)
            //         let var0 := mulmod(a_9_next_1, a_9_next_2, r)
            //         let var1 := addmod(a_9, var0, r)
            //         let a_9_next_3 := calldataload(0x2164)
            //         let var2 := sub(r, a_9_next_3)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(f_64, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_50 := calldataload(0x2ce4)
            //         let a_14 := calldataload(0x2404)
            //         let var0 := mulmod(f_50, a_14, r)
            //         let var1 := 0x1
            //         let var2 := sub(r, a_14)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(var0, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_50 := calldataload(0x2ce4)
            //         let a_14 := calldataload(0x2404)
            //         let var0 := mulmod(f_50, a_14, r)
            //         let a_15 := calldataload(0x21e4)
            //         let var1 := 0x0
            //         let var2 := sub(r, var1)
            //         let var3 := addmod(a_15, var2, r)
            //         let var4 := mulmod(var0, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_50 := calldataload(0x2ce4)
            //         let a_14 := calldataload(0x2404)
            //         let var0 := mulmod(f_50, a_14, r)
            //         let a_16 := calldataload(0x2204)
            //         let var1 := 0x0
            //         let var2 := sub(r, var1)
            //         let var3 := addmod(a_16, var2, r)
            //         let var4 := mulmod(var0, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_50 := calldataload(0x2ce4)
            //         let a_14 := calldataload(0x2404)
            //         let var0 := mulmod(f_50, a_14, r)
            //         let a_17 := calldataload(0x2224)
            //         let var1 := 0x0
            //         let var2 := sub(r, var1)
            //         let var3 := addmod(a_17, var2, r)
            //         let var4 := mulmod(var0, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_50 := calldataload(0x2ce4)
            //         let a_14 := calldataload(0x2404)
            //         let var0 := mulmod(f_50, a_14, r)
            //         let a_18 := calldataload(0x2244)
            //         let var1 := 0x0
            //         let var2 := sub(r, var1)
            //         let var3 := addmod(a_18, var2, r)
            //         let var4 := mulmod(var0, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_51 := calldataload(0x2d04)
            //         let a_14_prev_1 := calldataload(0x2424)
            //         let a_14 := calldataload(0x2404)
            //         let var0 := sub(r, a_14)
            //         let var1 := addmod(a_14_prev_1, var0, r)
            //         let var2 := mulmod(f_51, var1, r)
            //         let var3 := 0x1
            //         let var4 := sub(r, var1)
            //         let var5 := addmod(var3, var4, r)
            //         let var6 := mulmod(var2, var5, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var6,
            //             r
            //         )
            //     }
            //     {
            //         let f_51 := calldataload(0x2d04)
            //         let a_14 := calldataload(0x2404)
            //         let var0 := mulmod(f_51, a_14, r)
            //         let var1 := 0x1
            //         let var2 := sub(r, a_14)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(var0, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_52 := calldataload(0x2d24)
            //         let a_32 := calldataload(0x25e4)
            //         let var0 := mulmod(f_52, a_32, r)
            //         let var1 := 0x1
            //         let var2 := sub(r, a_32)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(var0, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_52 := calldataload(0x2d24)
            //         let a_32 := calldataload(0x25e4)
            //         let var0 := mulmod(f_52, a_32, r)
            //         let a_33 := calldataload(0x2544)
            //         let var1 := 0x0
            //         let var2 := sub(r, var1)
            //         let var3 := addmod(a_33, var2, r)
            //         let var4 := mulmod(var0, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let f_53 := calldataload(0x2d44)
            //         let a_32_prev_1 := calldataload(0x2604)
            //         let a_32 := calldataload(0x25e4)
            //         let var0 := sub(r, a_32)
            //         let var1 := addmod(a_32_prev_1, var0, r)
            //         let var2 := mulmod(f_53, var1, r)
            //         let var3 := 0x1
            //         let var4 := sub(r, var1)
            //         let var5 := addmod(var3, var4, r)
            //         let var6 := mulmod(var2, var5, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var6,
            //             r
            //         )
            //     }
            //     {
            //         let f_53 := calldataload(0x2d44)
            //         let a_32 := calldataload(0x25e4)
            //         let var0 := mulmod(f_53, a_32, r)
            //         let var1 := 0x1
            //         let var2 := sub(r, a_32)
            //         let var3 := addmod(var1, var2, r)
            //         let var4 := mulmod(var0, var3, r)
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             var4,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             sub(r, mulmod(l_0, calldataload(0x3524), r)),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let perm_z_last := calldataload(0x39a4)
            //         let eval := mulmod(
            //             mload(L_LAST_MPTR),
            //             addmod(
            //                 mulmod(perm_z_last, perm_z_last, r),
            //                 sub(r, perm_z_last),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3584),
            //                 sub(r, calldataload(0x3564)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x35e4),
            //                 sub(r, calldataload(0x35c4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3644),
            //                 sub(r, calldataload(0x3624)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x36a4),
            //                 sub(r, calldataload(0x3684)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3704),
            //                 sub(r, calldataload(0x36e4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3764),
            //                 sub(r, calldataload(0x3744)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x37c4),
            //                 sub(r, calldataload(0x37a4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3824),
            //                 sub(r, calldataload(0x3804)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3884),
            //                 sub(r, calldataload(0x3864)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x38e4),
            //                 sub(r, calldataload(0x38c4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3944),
            //                 sub(r, calldataload(0x3924)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x39a4),
            //                 sub(r, calldataload(0x3984)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x3544)
            //         let rhs := calldataload(0x3524)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x26a4),
            //                     mulmod(beta, calldataload(0x2ee4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x26c4),
            //                     mulmod(beta, calldataload(0x2f04), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x26e4),
            //                     mulmod(beta, calldataload(0x2f24), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2704),
            //                     mulmod(beta, calldataload(0x2f44), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(beta, mload(X_MPTR), r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x26a4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x26c4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x26e4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2704), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x35a4)
            //         let rhs := calldataload(0x3584)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2724),
            //                     mulmod(beta, calldataload(0x2f64), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2744),
            //                     mulmod(beta, calldataload(0x2f84), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2764),
            //                     mulmod(beta, calldataload(0x2fa4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2784),
            //                     mulmod(beta, calldataload(0x2fc4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2724), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2744), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2764), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2784), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x3604)
            //         let rhs := calldataload(0x35e4)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x27a4),
            //                     mulmod(beta, calldataload(0x2fe4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x27c4),
            //                     mulmod(beta, calldataload(0x3004), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x1c84),
            //                     mulmod(beta, calldataload(0x3024), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x1d04),
            //                     mulmod(beta, calldataload(0x3044), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x27a4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x27c4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x1c84), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x1d04), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x3664)
            //         let rhs := calldataload(0x3644)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x1d84),
            //                     mulmod(beta, calldataload(0x3064), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x1e04),
            //                     mulmod(beta, calldataload(0x3084), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x1e84),
            //                     mulmod(beta, calldataload(0x30a4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x1f04),
            //                     mulmod(beta, calldataload(0x30c4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x1d84), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x1e04), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x1e84), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x1f04), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x36c4)
            //         let rhs := calldataload(0x36a4)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x1f84),
            //                     mulmod(beta, calldataload(0x30e4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2004),
            //                     mulmod(beta, calldataload(0x3104), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2084),
            //                     mulmod(beta, calldataload(0x3124), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2104),
            //                     mulmod(beta, calldataload(0x3144), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x1f84), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2004), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2084), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2104), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x3724)
            //         let rhs := calldataload(0x3704)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2184),
            //                     mulmod(beta, calldataload(0x3164), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x21a4),
            //                     mulmod(beta, calldataload(0x3184), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x21c4),
            //                     mulmod(beta, calldataload(0x31a4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x21e4),
            //                     mulmod(beta, calldataload(0x31c4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2184), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x21a4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x21c4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x21e4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x3784)
            //         let rhs := calldataload(0x3764)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2204),
            //                     mulmod(beta, calldataload(0x31e4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2224),
            //                     mulmod(beta, calldataload(0x3204), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2244),
            //                     mulmod(beta, calldataload(0x3224), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2264),
            //                     mulmod(beta, calldataload(0x3244), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2204), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2224), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2244), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2264), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x37e4)
            //         let rhs := calldataload(0x37c4)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2284),
            //                     mulmod(beta, calldataload(0x3264), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x22a4),
            //                     mulmod(beta, calldataload(0x3284), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x22c4),
            //                     mulmod(beta, calldataload(0x32a4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x22e4),
            //                     mulmod(beta, calldataload(0x32c4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2284), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x22a4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x22c4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x22e4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x3844)
            //         let rhs := calldataload(0x3824)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2304),
            //                     mulmod(beta, calldataload(0x32e4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2324),
            //                     mulmod(beta, calldataload(0x3304), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2344),
            //                     mulmod(beta, calldataload(0x3324), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2364),
            //                     mulmod(beta, calldataload(0x3344), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2304), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2324), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2344), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2364), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x38a4)
            //         let rhs := calldataload(0x3884)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2384),
            //                     mulmod(beta, calldataload(0x3364), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x23a4),
            //                     mulmod(beta, calldataload(0x3384), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x23c4),
            //                     mulmod(beta, calldataload(0x33a4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x23e4),
            //                     mulmod(beta, calldataload(0x33c4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2384), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x23a4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x23c4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x23e4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x3904)
            //         let rhs := calldataload(0x38e4)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2404),
            //                     mulmod(beta, calldataload(0x33e4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2544),
            //                     mulmod(beta, calldataload(0x3404), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2564),
            //                     mulmod(beta, calldataload(0x3424), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2584),
            //                     mulmod(beta, calldataload(0x3444), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2404), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2544), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2564), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2584), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x3964)
            //         let rhs := calldataload(0x3944)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x25a4),
            //                     mulmod(beta, calldataload(0x3464), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x25c4),
            //                     mulmod(beta, calldataload(0x3484), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x25e4),
            //                     mulmod(beta, calldataload(0x34a4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2664),
            //                     mulmod(beta, calldataload(0x34c4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x25a4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x25c4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x25e4), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2664), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let gamma := mload(GAMMA_MPTR)
            //         let beta := mload(BETA_MPTR)
            //         let lhs := calldataload(0x39c4)
            //         let rhs := calldataload(0x39a4)
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     calldataload(0x2684),
            //                     mulmod(beta, calldataload(0x34e4), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         lhs := mulmod(
            //             lhs,
            //             addmod(
            //                 addmod(
            //                     mload(INSTANCE_EVAL_MPTR),
            //                     mulmod(beta, calldataload(0x3504), r),
            //                     r
            //                 ),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(calldataload(0x2684), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         mstore(0x00, mulmod(mload(0x00), delta, r))
            //         rhs := mulmod(
            //             rhs,
            //             addmod(
            //                 addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), r),
            //                 gamma,
            //                 r
            //             ),
            //             r
            //         )
            //         let left_sub_right := addmod(lhs, sub(r, rhs), r)
            //         let eval := addmod(
            //             left_sub_right,
            //             sub(
            //                 r,
            //                 mulmod(
            //                     left_sub_right,
            //                     addmod(
            //                         mload(L_LAST_MPTR),
            //                         mload(L_BLIND_MPTR),
            //                         r
            //                     ),
            //                     r
            //                 )
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x39e4)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x39e4),
            //                     calldataload(0x39e4),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x39e4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_10 := calldataload(0x2184)
            //             input := a_10
            //         }
            //         let table
            //         {
            //             let f_0 := calldataload(0x27e4)
            //             table := f_0
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x3a04),
            //             mulmod(
            //                 addmod(calldataload(0x3a24), beta, r),
            //                 addmod(calldataload(0x3a64), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x39e4),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3a24),
            //                 sub(r, calldataload(0x3a64)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x3a24),
            //                     sub(r, calldataload(0x3a64)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x3a24),
            //                     sub(r, calldataload(0x3a44)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x3a84)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x3a84),
            //                     calldataload(0x3a84),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x3a84)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_11 := calldataload(0x21a4)
            //             let a_12 := calldataload(0x21c4)
            //             input := a_11
            //             input := addmod(mulmod(input, theta, r), a_12, r)
            //         }
            //         let table
            //         {
            //             let f_11 := calldataload(0x2804)
            //             let f_12 := calldataload(0x2824)
            //             table := f_11
            //             table := addmod(mulmod(table, theta, r), f_12, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x3aa4),
            //             mulmod(
            //                 addmod(calldataload(0x3ac4), beta, r),
            //                 addmod(calldataload(0x3b04), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x3a84),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3ac4),
            //                 sub(r, calldataload(0x3b04)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x3ac4),
            //                     sub(r, calldataload(0x3b04)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x3ac4),
            //                     sub(r, calldataload(0x3ae4)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x3b24)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x3b24),
            //                     calldataload(0x3b24),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x3b24)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_13 := calldataload(0x23e4)
            //             let var0 := mulmod(a_14, a_13, r)
            //             let a_15 := calldataload(0x21e4)
            //             let var1 := mulmod(a_14, a_15, r)
            //             let var2 := 0x1
            //             let var3 := sub(r, a_14)
            //             let var4 := addmod(var2, var3, r)
            //             let var5 := 0x14
            //             let var6 := mulmod(var4, var5, r)
            //             let var7 := addmod(var1, var6, r)
            //             let a_15_next_1 := calldataload(0x2444)
            //             let var8 := mulmod(a_14, a_15_next_1, r)
            //             let var9 := addmod(var8, var6, r)
            //             let a_19 := calldataload(0x2264)
            //             let var10 := mulmod(a_14, a_19, r)
            //             input := var0
            //             input := addmod(mulmod(input, theta, r), var7, r)
            //             input := addmod(mulmod(input, theta, r), var9, r)
            //             input := addmod(mulmod(input, theta, r), var10, r)
            //         }
            //         let table
            //         {
            //             let f_13 := calldataload(0x2844)
            //             let f_14 := calldataload(0x2864)
            //             let f_15 := calldataload(0x2884)
            //             let f_16 := calldataload(0x28a4)
            //             table := f_13
            //             table := addmod(mulmod(table, theta, r), f_14, r)
            //             table := addmod(mulmod(table, theta, r), f_15, r)
            //             table := addmod(mulmod(table, theta, r), f_16, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x3b44),
            //             mulmod(
            //                 addmod(calldataload(0x3b64), beta, r),
            //                 addmod(calldataload(0x3ba4), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x3b24),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3b64),
            //                 sub(r, calldataload(0x3ba4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x3b64),
            //                     sub(r, calldataload(0x3ba4)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x3b64),
            //                     sub(r, calldataload(0x3b84)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x3bc4)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x3bc4),
            //                     calldataload(0x3bc4),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x3bc4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_23 := calldataload(0x22e4)
            //             let var0 := mulmod(a_14, a_23, r)
            //             let a_19 := calldataload(0x2264)
            //             let var1 := mulmod(var0, a_19, r)
            //             let a_15 := calldataload(0x21e4)
            //             let var2 := mulmod(var0, a_15, r)
            //             let var3 := 0x1
            //             let var4 := sub(r, var0)
            //             let var5 := addmod(var3, var4, r)
            //             let var6 := 0x14
            //             let var7 := mulmod(var5, var6, r)
            //             let var8 := addmod(var2, var7, r)
            //             input := var1
            //             input := addmod(mulmod(input, theta, r), var8, r)
            //             input := addmod(mulmod(input, theta, r), var6, r)
            //         }
            //         let table
            //         {
            //             let f_17 := calldataload(0x28c4)
            //             let f_18 := calldataload(0x28e4)
            //             let f_19 := calldataload(0x2904)
            //             table := f_17
            //             table := addmod(mulmod(table, theta, r), f_18, r)
            //             table := addmod(mulmod(table, theta, r), f_19, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x3be4),
            //             mulmod(
            //                 addmod(calldataload(0x3c04), beta, r),
            //                 addmod(calldataload(0x3c44), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x3bc4),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3c04),
            //                 sub(r, calldataload(0x3c44)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x3c04),
            //                     sub(r, calldataload(0x3c44)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x3c04),
            //                     sub(r, calldataload(0x3c24)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x3c64)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x3c64),
            //                     calldataload(0x3c64),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x3c64)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_27_next_1 := calldataload(0x2464)
            //             let var0 := mulmod(a_14, a_27_next_1, r)
            //             let a_19 := calldataload(0x2264)
            //             let var1 := mulmod(var0, a_19, r)
            //             let var2 := 0x14
            //             let a_15_next_1 := calldataload(0x2444)
            //             let var3 := mulmod(var0, a_15_next_1, r)
            //             let var4 := 0x1
            //             let var5 := sub(r, var0)
            //             let var6 := addmod(var4, var5, r)
            //             let var7 := mulmod(var6, var2, r)
            //             let var8 := addmod(var3, var7, r)
            //             input := var1
            //             input := addmod(mulmod(input, theta, r), var2, r)
            //             input := addmod(mulmod(input, theta, r), var8, r)
            //         }
            //         let table
            //         {
            //             let f_17 := calldataload(0x28c4)
            //             let f_18 := calldataload(0x28e4)
            //             let f_19 := calldataload(0x2904)
            //             table := f_17
            //             table := addmod(mulmod(table, theta, r), f_18, r)
            //             table := addmod(mulmod(table, theta, r), f_19, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x3c84),
            //             mulmod(
            //                 addmod(calldataload(0x3ca4), beta, r),
            //                 addmod(calldataload(0x3ce4), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x3c64),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3ca4),
            //                 sub(r, calldataload(0x3ce4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x3ca4),
            //                     sub(r, calldataload(0x3ce4)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x3ca4),
            //                     sub(r, calldataload(0x3cc4)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x3d04)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x3d04),
            //                     calldataload(0x3d04),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x3d04)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_13 := calldataload(0x23e4)
            //             let var0 := mulmod(a_14, a_13, r)
            //             let a_16 := calldataload(0x2204)
            //             let var1 := mulmod(a_14, a_16, r)
            //             let var2 := 0x1
            //             let var3 := sub(r, a_14)
            //             let var4 := addmod(var2, var3, r)
            //             let var5 := 0x12
            //             let var6 := mulmod(var4, var5, r)
            //             let var7 := addmod(var1, var6, r)
            //             let a_16_next_1 := calldataload(0x2484)
            //             let var8 := mulmod(a_14, a_16_next_1, r)
            //             let var9 := addmod(var8, var6, r)
            //             let a_20 := calldataload(0x2284)
            //             let var10 := mulmod(a_14, a_20, r)
            //             input := var0
            //             input := addmod(mulmod(input, theta, r), var7, r)
            //             input := addmod(mulmod(input, theta, r), var9, r)
            //             input := addmod(mulmod(input, theta, r), var10, r)
            //         }
            //         let table
            //         {
            //             let f_20 := calldataload(0x2924)
            //             let f_21 := calldataload(0x2944)
            //             let f_22 := calldataload(0x2964)
            //             let f_23 := calldataload(0x2984)
            //             table := f_20
            //             table := addmod(mulmod(table, theta, r), f_21, r)
            //             table := addmod(mulmod(table, theta, r), f_22, r)
            //             table := addmod(mulmod(table, theta, r), f_23, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x3d24),
            //             mulmod(
            //                 addmod(calldataload(0x3d44), beta, r),
            //                 addmod(calldataload(0x3d84), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x3d04),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3d44),
            //                 sub(r, calldataload(0x3d84)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x3d44),
            //                     sub(r, calldataload(0x3d84)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x3d44),
            //                     sub(r, calldataload(0x3d64)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x3da4)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x3da4),
            //                     calldataload(0x3da4),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x3da4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_24 := calldataload(0x2304)
            //             let var0 := mulmod(a_14, a_24, r)
            //             let a_20 := calldataload(0x2284)
            //             let var1 := mulmod(var0, a_20, r)
            //             let a_16 := calldataload(0x2204)
            //             let var2 := mulmod(var0, a_16, r)
            //             let var3 := 0x1
            //             let var4 := sub(r, var0)
            //             let var5 := addmod(var3, var4, r)
            //             let var6 := 0x12
            //             let var7 := mulmod(var5, var6, r)
            //             let var8 := addmod(var2, var7, r)
            //             input := var1
            //             input := addmod(mulmod(input, theta, r), var8, r)
            //             input := addmod(mulmod(input, theta, r), var6, r)
            //         }
            //         let table
            //         {
            //             let f_24 := calldataload(0x29a4)
            //             let f_25 := calldataload(0x29c4)
            //             let f_26 := calldataload(0x29e4)
            //             table := f_24
            //             table := addmod(mulmod(table, theta, r), f_25, r)
            //             table := addmod(mulmod(table, theta, r), f_26, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x3dc4),
            //             mulmod(
            //                 addmod(calldataload(0x3de4), beta, r),
            //                 addmod(calldataload(0x3e24), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x3da4),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3de4),
            //                 sub(r, calldataload(0x3e24)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x3de4),
            //                     sub(r, calldataload(0x3e24)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x3de4),
            //                     sub(r, calldataload(0x3e04)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x3e44)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x3e44),
            //                     calldataload(0x3e44),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x3e44)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_28_next_1 := calldataload(0x24a4)
            //             let var0 := mulmod(a_14, a_28_next_1, r)
            //             let a_20 := calldataload(0x2284)
            //             let var1 := mulmod(var0, a_20, r)
            //             let var2 := 0x12
            //             let a_16_next_1 := calldataload(0x2484)
            //             let var3 := mulmod(var0, a_16_next_1, r)
            //             let var4 := 0x1
            //             let var5 := sub(r, var0)
            //             let var6 := addmod(var4, var5, r)
            //             let var7 := mulmod(var6, var2, r)
            //             let var8 := addmod(var3, var7, r)
            //             input := var1
            //             input := addmod(mulmod(input, theta, r), var2, r)
            //             input := addmod(mulmod(input, theta, r), var8, r)
            //         }
            //         let table
            //         {
            //             let f_24 := calldataload(0x29a4)
            //             let f_25 := calldataload(0x29c4)
            //             let f_26 := calldataload(0x29e4)
            //             table := f_24
            //             table := addmod(mulmod(table, theta, r), f_25, r)
            //             table := addmod(mulmod(table, theta, r), f_26, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x3e64),
            //             mulmod(
            //                 addmod(calldataload(0x3e84), beta, r),
            //                 addmod(calldataload(0x3ec4), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x3e44),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3e84),
            //                 sub(r, calldataload(0x3ec4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x3e84),
            //                     sub(r, calldataload(0x3ec4)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x3e84),
            //                     sub(r, calldataload(0x3ea4)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x3ee4)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x3ee4),
            //                     calldataload(0x3ee4),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x3ee4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_13 := calldataload(0x23e4)
            //             let var0 := mulmod(a_14, a_13, r)
            //             let a_17 := calldataload(0x2224)
            //             let var1 := mulmod(a_14, a_17, r)
            //             let var2 := 0x1
            //             let var3 := sub(r, a_14)
            //             let var4 := addmod(var2, var3, r)
            //             let var5 := 0x12
            //             let var6 := mulmod(var4, var5, r)
            //             let var7 := addmod(var1, var6, r)
            //             let a_17_next_1 := calldataload(0x24c4)
            //             let var8 := mulmod(a_14, a_17_next_1, r)
            //             let var9 := addmod(var8, var6, r)
            //             let a_21 := calldataload(0x22a4)
            //             let var10 := mulmod(a_14, a_21, r)
            //             input := var0
            //             input := addmod(mulmod(input, theta, r), var7, r)
            //             input := addmod(mulmod(input, theta, r), var9, r)
            //             input := addmod(mulmod(input, theta, r), var10, r)
            //         }
            //         let table
            //         {
            //             let f_27 := calldataload(0x2a04)
            //             let f_28 := calldataload(0x2a24)
            //             let f_29 := calldataload(0x2a44)
            //             let f_30 := calldataload(0x2a64)
            //             table := f_27
            //             table := addmod(mulmod(table, theta, r), f_28, r)
            //             table := addmod(mulmod(table, theta, r), f_29, r)
            //             table := addmod(mulmod(table, theta, r), f_30, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x3f04),
            //             mulmod(
            //                 addmod(calldataload(0x3f24), beta, r),
            //                 addmod(calldataload(0x3f64), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x3ee4),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3f24),
            //                 sub(r, calldataload(0x3f64)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x3f24),
            //                     sub(r, calldataload(0x3f64)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x3f24),
            //                     sub(r, calldataload(0x3f44)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x3f84)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x3f84),
            //                     calldataload(0x3f84),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x3f84)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_25 := calldataload(0x2324)
            //             let var0 := mulmod(a_14, a_25, r)
            //             let a_21 := calldataload(0x22a4)
            //             let var1 := mulmod(var0, a_21, r)
            //             let a_17 := calldataload(0x2224)
            //             let var2 := mulmod(var0, a_17, r)
            //             let var3 := 0x1
            //             let var4 := sub(r, var0)
            //             let var5 := addmod(var3, var4, r)
            //             let var6 := 0x12
            //             let var7 := mulmod(var5, var6, r)
            //             let var8 := addmod(var2, var7, r)
            //             input := var1
            //             input := addmod(mulmod(input, theta, r), var8, r)
            //             input := addmod(mulmod(input, theta, r), var6, r)
            //         }
            //         let table
            //         {
            //             let f_31 := calldataload(0x2a84)
            //             let f_32 := calldataload(0x2aa4)
            //             let f_33 := calldataload(0x2ac4)
            //             table := f_31
            //             table := addmod(mulmod(table, theta, r), f_32, r)
            //             table := addmod(mulmod(table, theta, r), f_33, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x3fa4),
            //             mulmod(
            //                 addmod(calldataload(0x3fc4), beta, r),
            //                 addmod(calldataload(0x4004), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x3f84),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x3fc4),
            //                 sub(r, calldataload(0x4004)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x3fc4),
            //                     sub(r, calldataload(0x4004)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x3fc4),
            //                     sub(r, calldataload(0x3fe4)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x4024)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x4024),
            //                     calldataload(0x4024),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x4024)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_29_next_1 := calldataload(0x24e4)
            //             let var0 := mulmod(a_14, a_29_next_1, r)
            //             let a_21 := calldataload(0x22a4)
            //             let var1 := mulmod(var0, a_21, r)
            //             let var2 := 0x12
            //             let a_17_next_1 := calldataload(0x24c4)
            //             let var3 := mulmod(var0, a_17_next_1, r)
            //             let var4 := 0x1
            //             let var5 := sub(r, var0)
            //             let var6 := addmod(var4, var5, r)
            //             let var7 := mulmod(var6, var2, r)
            //             let var8 := addmod(var3, var7, r)
            //             input := var1
            //             input := addmod(mulmod(input, theta, r), var2, r)
            //             input := addmod(mulmod(input, theta, r), var8, r)
            //         }
            //         let table
            //         {
            //             let f_31 := calldataload(0x2a84)
            //             let f_32 := calldataload(0x2aa4)
            //             let f_33 := calldataload(0x2ac4)
            //             table := f_31
            //             table := addmod(mulmod(table, theta, r), f_32, r)
            //             table := addmod(mulmod(table, theta, r), f_33, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x4044),
            //             mulmod(
            //                 addmod(calldataload(0x4064), beta, r),
            //                 addmod(calldataload(0x40a4), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x4024),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x4064),
            //                 sub(r, calldataload(0x40a4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x4064),
            //                     sub(r, calldataload(0x40a4)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x4064),
            //                     sub(r, calldataload(0x4084)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x40c4)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x40c4),
            //                     calldataload(0x40c4),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x40c4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_13 := calldataload(0x23e4)
            //             let var0 := mulmod(a_14, a_13, r)
            //             let a_18 := calldataload(0x2244)
            //             let var1 := mulmod(a_14, a_18, r)
            //             let var2 := 0x1
            //             let var3 := sub(r, a_14)
            //             let var4 := addmod(var2, var3, r)
            //             let var5 := 0x1d
            //             let var6 := mulmod(var4, var5, r)
            //             let var7 := addmod(var1, var6, r)
            //             let a_18_next_1 := calldataload(0x2504)
            //             let var8 := mulmod(a_14, a_18_next_1, r)
            //             let var9 := addmod(var8, var6, r)
            //             let a_22 := calldataload(0x22c4)
            //             let var10 := mulmod(a_14, a_22, r)
            //             input := var0
            //             input := addmod(mulmod(input, theta, r), var7, r)
            //             input := addmod(mulmod(input, theta, r), var9, r)
            //             input := addmod(mulmod(input, theta, r), var10, r)
            //         }
            //         let table
            //         {
            //             let f_34 := calldataload(0x2ae4)
            //             let f_35 := calldataload(0x2b04)
            //             let f_36 := calldataload(0x2b24)
            //             let f_37 := calldataload(0x2b44)
            //             table := f_34
            //             table := addmod(mulmod(table, theta, r), f_35, r)
            //             table := addmod(mulmod(table, theta, r), f_36, r)
            //             table := addmod(mulmod(table, theta, r), f_37, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x40e4),
            //             mulmod(
            //                 addmod(calldataload(0x4104), beta, r),
            //                 addmod(calldataload(0x4144), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x40c4),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x4104),
            //                 sub(r, calldataload(0x4144)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x4104),
            //                     sub(r, calldataload(0x4144)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x4104),
            //                     sub(r, calldataload(0x4124)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x4164)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x4164),
            //                     calldataload(0x4164),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x4164)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_26 := calldataload(0x2344)
            //             let var0 := mulmod(a_14, a_26, r)
            //             let a_22 := calldataload(0x22c4)
            //             let var1 := mulmod(var0, a_22, r)
            //             let a_18 := calldataload(0x2244)
            //             let var2 := mulmod(var0, a_18, r)
            //             let var3 := 0x1
            //             let var4 := sub(r, var0)
            //             let var5 := addmod(var3, var4, r)
            //             let var6 := 0x1d
            //             let var7 := mulmod(var5, var6, r)
            //             let var8 := addmod(var2, var7, r)
            //             input := var1
            //             input := addmod(mulmod(input, theta, r), var8, r)
            //             input := addmod(mulmod(input, theta, r), var6, r)
            //         }
            //         let table
            //         {
            //             let f_38 := calldataload(0x2b64)
            //             let f_39 := calldataload(0x2b84)
            //             let f_40 := calldataload(0x2ba4)
            //             table := f_38
            //             table := addmod(mulmod(table, theta, r), f_39, r)
            //             table := addmod(mulmod(table, theta, r), f_40, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x4184),
            //             mulmod(
            //                 addmod(calldataload(0x41a4), beta, r),
            //                 addmod(calldataload(0x41e4), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x4164),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x41a4),
            //                 sub(r, calldataload(0x41e4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x41a4),
            //                     sub(r, calldataload(0x41e4)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x41a4),
            //                     sub(r, calldataload(0x41c4)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x4204)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x4204),
            //                     calldataload(0x4204),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x4204)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_14 := calldataload(0x2404)
            //             let a_30_next_1 := calldataload(0x2524)
            //             let var0 := mulmod(a_14, a_30_next_1, r)
            //             let a_22 := calldataload(0x22c4)
            //             let var1 := mulmod(var0, a_22, r)
            //             let var2 := 0x1d
            //             let a_18_next_1 := calldataload(0x2504)
            //             let var3 := mulmod(var0, a_18_next_1, r)
            //             let var4 := 0x1
            //             let var5 := sub(r, var0)
            //             let var6 := addmod(var4, var5, r)
            //             let var7 := mulmod(var6, var2, r)
            //             let var8 := addmod(var3, var7, r)
            //             input := var1
            //             input := addmod(mulmod(input, theta, r), var2, r)
            //             input := addmod(mulmod(input, theta, r), var8, r)
            //         }
            //         let table
            //         {
            //             let f_38 := calldataload(0x2b64)
            //             let f_39 := calldataload(0x2b84)
            //             let f_40 := calldataload(0x2ba4)
            //             table := f_38
            //             table := addmod(mulmod(table, theta, r), f_39, r)
            //             table := addmod(mulmod(table, theta, r), f_40, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x4224),
            //             mulmod(
            //                 addmod(calldataload(0x4244), beta, r),
            //                 addmod(calldataload(0x4284), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x4204),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x4244),
            //                 sub(r, calldataload(0x4284)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x4244),
            //                     sub(r, calldataload(0x4284)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x4244),
            //                     sub(r, calldataload(0x4264)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x42a4)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x42a4),
            //                     calldataload(0x42a4),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x42a4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_32 := calldataload(0x25e4)
            //             let a_31 := calldataload(0x25c4)
            //             let var0 := mulmod(a_32, a_31, r)
            //             let a_33 := calldataload(0x2544)
            //             let var1 := mulmod(a_32, a_33, r)
            //             let var2 := 0x1
            //             let var3 := sub(r, a_32)
            //             let var4 := addmod(var2, var3, r)
            //             let var5 := 0x5c
            //             let var6 := mulmod(var4, var5, r)
            //             let var7 := addmod(var1, var6, r)
            //             let a_33_next_1 := calldataload(0x2624)
            //             let var8 := mulmod(a_32, a_33_next_1, r)
            //             let var9 := addmod(var8, var6, r)
            //             let a_34 := calldataload(0x2564)
            //             let var10 := mulmod(a_32, a_34, r)
            //             input := var0
            //             input := addmod(mulmod(input, theta, r), var7, r)
            //             input := addmod(mulmod(input, theta, r), var9, r)
            //             input := addmod(mulmod(input, theta, r), var10, r)
            //         }
            //         let table
            //         {
            //             let f_41 := calldataload(0x2bc4)
            //             let f_42 := calldataload(0x2be4)
            //             let f_43 := calldataload(0x2c04)
            //             let f_44 := calldataload(0x2c24)
            //             table := f_41
            //             table := addmod(mulmod(table, theta, r), f_42, r)
            //             table := addmod(mulmod(table, theta, r), f_43, r)
            //             table := addmod(mulmod(table, theta, r), f_44, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x42c4),
            //             mulmod(
            //                 addmod(calldataload(0x42e4), beta, r),
            //                 addmod(calldataload(0x4324), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x42a4),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x42e4),
            //                 sub(r, calldataload(0x4324)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x42e4),
            //                     sub(r, calldataload(0x4324)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x42e4),
            //                     sub(r, calldataload(0x4304)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x4344)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x4344),
            //                     calldataload(0x4344),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x4344)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_32 := calldataload(0x25e4)
            //             let a_35 := calldataload(0x2584)
            //             let var0 := mulmod(a_32, a_35, r)
            //             let a_34 := calldataload(0x2564)
            //             let var1 := mulmod(var0, a_34, r)
            //             let a_33 := calldataload(0x2544)
            //             let var2 := mulmod(var0, a_33, r)
            //             let var3 := 0x1
            //             let var4 := sub(r, var0)
            //             let var5 := addmod(var3, var4, r)
            //             let var6 := 0x5c
            //             let var7 := mulmod(var5, var6, r)
            //             let var8 := addmod(var2, var7, r)
            //             input := var1
            //             input := addmod(mulmod(input, theta, r), var8, r)
            //             input := addmod(mulmod(input, theta, r), var6, r)
            //         }
            //         let table
            //         {
            //             let f_45 := calldataload(0x2c44)
            //             let f_46 := calldataload(0x2c64)
            //             let f_47 := calldataload(0x2c84)
            //             table := f_45
            //             table := addmod(mulmod(table, theta, r), f_46, r)
            //             table := addmod(mulmod(table, theta, r), f_47, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x4364),
            //             mulmod(
            //                 addmod(calldataload(0x4384), beta, r),
            //                 addmod(calldataload(0x43c4), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x4344),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x4384),
            //                 sub(r, calldataload(0x43c4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x4384),
            //                     sub(r, calldataload(0x43c4)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x4384),
            //                     sub(r, calldataload(0x43a4)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x43e4)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x43e4),
            //                     calldataload(0x43e4),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x43e4)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let a_32 := calldataload(0x25e4)
            //             let a_36_next_1 := calldataload(0x2644)
            //             let var0 := mulmod(a_32, a_36_next_1, r)
            //             let a_34 := calldataload(0x2564)
            //             let var1 := mulmod(var0, a_34, r)
            //             let var2 := 0x5c
            //             let a_33_next_1 := calldataload(0x2624)
            //             let var3 := mulmod(var0, a_33_next_1, r)
            //             let var4 := 0x1
            //             let var5 := sub(r, var0)
            //             let var6 := addmod(var4, var5, r)
            //             let var7 := mulmod(var6, var2, r)
            //             let var8 := addmod(var3, var7, r)
            //             input := var1
            //             input := addmod(mulmod(input, theta, r), var2, r)
            //             input := addmod(mulmod(input, theta, r), var8, r)
            //         }
            //         let table
            //         {
            //             let f_45 := calldataload(0x2c44)
            //             let f_46 := calldataload(0x2c64)
            //             let f_47 := calldataload(0x2c84)
            //             table := f_45
            //             table := addmod(mulmod(table, theta, r), f_46, r)
            //             table := addmod(mulmod(table, theta, r), f_47, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x4404),
            //             mulmod(
            //                 addmod(calldataload(0x4424), beta, r),
            //                 addmod(calldataload(0x4464), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x43e4),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x4424),
            //                 sub(r, calldataload(0x4464)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x4424),
            //                     sub(r, calldataload(0x4464)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x4424),
            //                     sub(r, calldataload(0x4444)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_0 := mload(L_0_MPTR)
            //         let eval := addmod(
            //             l_0,
            //             mulmod(l_0, sub(r, calldataload(0x4484)), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let l_last := mload(L_LAST_MPTR)
            //         let eval := mulmod(
            //             l_last,
            //             addmod(
            //                 mulmod(
            //                     calldataload(0x4484),
            //                     calldataload(0x4484),
            //                     r
            //                 ),
            //                 sub(r, calldataload(0x4484)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let theta := mload(THETA_MPTR)
            //         let input
            //         {
            //             let f_54 := calldataload(0x2d64)
            //             let a_37 := calldataload(0x2664)
            //             let var0 := mulmod(f_54, a_37, r)
            //             let var1 := 0x1
            //             let var2 := sub(r, f_54)
            //             let var3 := addmod(var1, var2, r)
            //             let var4 := 0x100
            //             let var5 := mulmod(var3, var4, r)
            //             let var6 := addmod(var0, var5, r)
            //             let a_38 := calldataload(0x2684)
            //             let var7 := mulmod(f_54, a_38, r)
            //             let var8 := 0x40
            //             let var9 := mulmod(var3, var8, r)
            //             let var10 := addmod(var7, var9, r)
            //             input := var6
            //             input := addmod(mulmod(input, theta, r), var10, r)
            //         }
            //         let table
            //         {
            //             let f_48 := calldataload(0x2ca4)
            //             let f_49 := calldataload(0x2cc4)
            //             table := f_48
            //             table := addmod(mulmod(table, theta, r), f_49, r)
            //         }
            //         let beta := mload(BETA_MPTR)
            //         let gamma := mload(GAMMA_MPTR)
            //         let lhs := mulmod(
            //             calldataload(0x44a4),
            //             mulmod(
            //                 addmod(calldataload(0x44c4), beta, r),
            //                 addmod(calldataload(0x4504), gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let rhs := mulmod(
            //             calldataload(0x4484),
            //             mulmod(
            //                 addmod(input, beta, r),
            //                 addmod(table, gamma, r),
            //                 r
            //             ),
            //             r
            //         )
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             addmod(lhs, sub(r, rhs), r),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             mload(L_0_MPTR),
            //             addmod(
            //                 calldataload(0x44c4),
            //                 sub(r, calldataload(0x4504)),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }
            //     {
            //         let eval := mulmod(
            //             addmod(
            //                 1,
            //                 sub(
            //                     r,
            //                     addmod(
            //                         mload(L_BLIND_MPTR),
            //                         mload(L_LAST_MPTR),
            //                         r
            //                     )
            //                 ),
            //                 r
            //             ),
            //             mulmod(
            //                 addmod(
            //                     calldataload(0x44c4),
            //                     sub(r, calldataload(0x4504)),
            //                     r
            //                 ),
            //                 addmod(
            //                     calldataload(0x44c4),
            //                     sub(r, calldataload(0x44e4)),
            //                     r
            //                 ),
            //                 r
            //             ),
            //             r
            //         )
            //         quotient_eval_numer := addmod(
            //             mulmod(quotient_eval_numer, y, r),
            //             eval,
            //             r
            //         )
            //     }

            //     pop(y)
            //     pop(delta)

            //     let quotient_eval := mulmod(
            //         quotient_eval_numer,
            //         mload(X_N_MINUS_1_INV_MPTR),
            //         r
            //     )
            //     mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            // }

            // // Compute quotient commitment
            // {
            //     mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
            //     mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
            //     let x_n := mload(X_N_MPTR)
            //     for {
            //         let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
            //         let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
            //     } lt(cptr_end, cptr) {

            //     } {
            //         success := ec_mul_acc(success, x_n)
            //         success := ec_add_acc(
            //             success,
            //             calldataload(cptr),
            //             calldataload(add(cptr, 0x20))
            //         )
            //         cptr := sub(cptr, 0x40)
            //     }
            //     mstore(QUOTIENT_X_MPTR, mload(0x00))
            //     mstore(QUOTIENT_Y_MPTR, mload(0x20))
            // }

            // Compute pairing lhs and rhs
            // {
            //     {
            //         let x := mload(X_MPTR)
            //         let omega := mload(OMEGA_MPTR)
            //         let omega_inv := mload(OMEGA_INV_MPTR)
            //         let x_pow_of_omega := mulmod(x, omega, r)
            //         mstore(0x0460, x_pow_of_omega)
            //         x_pow_of_omega := mulmod(x_pow_of_omega, omega, r)
            //         mstore(0x0480, x_pow_of_omega)
            //         x_pow_of_omega := mulmod(x_pow_of_omega, omega, r)
            //         mstore(0x04a0, x_pow_of_omega)
            //         mstore(0x0440, x)
            //         x_pow_of_omega := mulmod(x, omega_inv, r)
            //         mstore(0x0420, x_pow_of_omega)
            //         x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
            //         x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
            //         x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
            //         x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
            //         x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
            //         x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
            //         mstore(0x0400, x_pow_of_omega)
            //     }
            //     {
            //         let mu := mload(MU_MPTR)
            //         for {
            //             let mptr := 0x04c0
            //             let mptr_end := 0x0580
            //             let point_mptr := 0x0400
            //         } lt(mptr, mptr_end) {
            //             mptr := add(mptr, 0x20)
            //             point_mptr := add(point_mptr, 0x20)
            //         } {
            //             mstore(mptr, addmod(mu, sub(r, mload(point_mptr)), r))
            //         }
            //         let s
            //         s := mload(0x0500)
            //         s := mulmod(s, mload(0x0520), r)
            //         s := mulmod(s, mload(0x0540), r)
            //         s := mulmod(s, mload(0x0560), r)
            //         mstore(0x0580, s)
            //         let diff
            //         diff := mload(0x04c0)
            //         diff := mulmod(diff, mload(0x04e0), r)
            //         mstore(0x05a0, diff)
            //         mstore(0x00, diff)
            //         diff := mload(0x04c0)
            //         diff := mulmod(diff, mload(0x04e0), r)
            //         diff := mulmod(diff, mload(0x0520), r)
            //         diff := mulmod(diff, mload(0x0540), r)
            //         diff := mulmod(diff, mload(0x0560), r)
            //         mstore(0x05c0, diff)
            //         diff := mload(0x04c0)
            //         diff := mulmod(diff, mload(0x04e0), r)
            //         diff := mulmod(diff, mload(0x0540), r)
            //         diff := mulmod(diff, mload(0x0560), r)
            //         mstore(0x05e0, diff)
            //         diff := mload(0x04c0)
            //         diff := mulmod(diff, mload(0x0520), r)
            //         diff := mulmod(diff, mload(0x0540), r)
            //         diff := mulmod(diff, mload(0x0560), r)
            //         mstore(0x0600, diff)
            //         diff := mload(0x04e0)
            //         diff := mulmod(diff, mload(0x0540), r)
            //         diff := mulmod(diff, mload(0x0560), r)
            //         mstore(0x0620, diff)
            //     }
            //     {
            //         let point_2 := mload(0x0440)
            //         let point_3 := mload(0x0460)
            //         let point_4 := mload(0x0480)
            //         let point_5 := mload(0x04a0)
            //         let coeff
            //         coeff := addmod(point_2, sub(r, point_3), r)
            //         coeff := mulmod(
            //             coeff,
            //             addmod(point_2, sub(r, point_4), r),
            //             r
            //         )
            //         coeff := mulmod(
            //             coeff,
            //             addmod(point_2, sub(r, point_5), r),
            //             r
            //         )
            //         coeff := mulmod(coeff, mload(0x0500), r)
            //         mstore(0x20, coeff)
            //         coeff := addmod(point_3, sub(r, point_2), r)
            //         coeff := mulmod(
            //             coeff,
            //             addmod(point_3, sub(r, point_4), r),
            //             r
            //         )
            //         coeff := mulmod(
            //             coeff,
            //             addmod(point_3, sub(r, point_5), r),
            //             r
            //         )
            //         coeff := mulmod(coeff, mload(0x0520), r)
            //         mstore(0x40, coeff)
            //         coeff := addmod(point_4, sub(r, point_2), r)
            //         coeff := mulmod(
            //             coeff,
            //             addmod(point_4, sub(r, point_3), r),
            //             r
            //         )
            //         coeff := mulmod(
            //             coeff,
            //             addmod(point_4, sub(r, point_5), r),
            //             r
            //         )
            //         coeff := mulmod(coeff, mload(0x0540), r)
            //         mstore(0x60, coeff)
            //         coeff := addmod(point_5, sub(r, point_2), r)
            //         coeff := mulmod(
            //             coeff,
            //             addmod(point_5, sub(r, point_3), r),
            //             r
            //         )
            //         coeff := mulmod(
            //             coeff,
            //             addmod(point_5, sub(r, point_4), r),
            //             r
            //         )
            //         coeff := mulmod(coeff, mload(0x0560), r)
            //         mstore(0x80, coeff)
            //     }
            //     {
            //         let point_2 := mload(0x0440)
            //         let coeff
            //         coeff := 1
            //         coeff := mulmod(coeff, mload(0x0500), r)
            //         mstore(0xa0, coeff)
            //     }
            //     {
            //         let point_2 := mload(0x0440)
            //         let point_3 := mload(0x0460)
            //         let coeff
            //         coeff := addmod(point_2, sub(r, point_3), r)
            //         coeff := mulmod(coeff, mload(0x0500), r)
            //         mstore(0xc0, coeff)
            //         coeff := addmod(point_3, sub(r, point_2), r)
            //         coeff := mulmod(coeff, mload(0x0520), r)
            //         mstore(0xe0, coeff)
            //     }
            //     {
            //         let point_1 := mload(0x0420)
            //         let point_2 := mload(0x0440)
            //         let coeff
            //         coeff := addmod(point_1, sub(r, point_2), r)
            //         coeff := mulmod(coeff, mload(0x04e0), r)
            //         mstore(0x0100, coeff)
            //         coeff := addmod(point_2, sub(r, point_1), r)
            //         coeff := mulmod(coeff, mload(0x0500), r)
            //         mstore(0x0120, coeff)
            //     }
            //     {
            //         let point_0 := mload(0x0400)
            //         let point_2 := mload(0x0440)
            //         let point_3 := mload(0x0460)
            //         let coeff
            //         coeff := addmod(point_0, sub(r, point_2), r)
            //         coeff := mulmod(
            //             coeff,
            //             addmod(point_0, sub(r, point_3), r),
            //             r
            //         )
            //         coeff := mulmod(coeff, mload(0x04c0), r)
            //         mstore(0x0140, coeff)
            //         coeff := addmod(point_2, sub(r, point_0), r)
            //         coeff := mulmod(
            //             coeff,
            //             addmod(point_2, sub(r, point_3), r),
            //             r
            //         )
            //         coeff := mulmod(coeff, mload(0x0500), r)
            //         mstore(0x0160, coeff)
            //         coeff := addmod(point_3, sub(r, point_0), r)
            //         coeff := mulmod(
            //             coeff,
            //             addmod(point_3, sub(r, point_2), r),
            //             r
            //         )
            //         coeff := mulmod(coeff, mload(0x0520), r)
            //         mstore(0x0180, coeff)
            //     }
            //     {
            //         success := batch_invert(success, 0x01a0, r)
            //         let diff_0_inv := mload(0x00)
            //         mstore(0x05a0, diff_0_inv)
            //         for {
            //             let mptr := 0x05c0
            //             let mptr_end := 0x0640
            //         } lt(mptr, mptr_end) {
            //             mptr := add(mptr, 0x20)
            //         } {
            //             mstore(mptr, mulmod(mload(mptr), diff_0_inv, r))
            //         }
            //     }
            //     {
            //         let zeta := mload(ZETA_MPTR)
            //         let r_eval := 0
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x20), calldataload(0x2104), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x40), calldataload(0x2124), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x60), calldataload(0x2144), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x80), calldataload(0x2164), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x20), calldataload(0x2084), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x40), calldataload(0x20a4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x60), calldataload(0x20c4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x80), calldataload(0x20e4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x20), calldataload(0x2004), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x40), calldataload(0x2024), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x60), calldataload(0x2044), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x80), calldataload(0x2064), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x20), calldataload(0x1f84), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x40), calldataload(0x1fa4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x60), calldataload(0x1fc4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x80), calldataload(0x1fe4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x20), calldataload(0x1f04), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x40), calldataload(0x1f24), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x60), calldataload(0x1f44), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x80), calldataload(0x1f64), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x20), calldataload(0x1e84), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x40), calldataload(0x1ea4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x60), calldataload(0x1ec4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x80), calldataload(0x1ee4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x20), calldataload(0x1e04), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x40), calldataload(0x1e24), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x60), calldataload(0x1e44), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x80), calldataload(0x1e64), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x20), calldataload(0x1d84), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x40), calldataload(0x1da4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x60), calldataload(0x1dc4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x80), calldataload(0x1de4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x20), calldataload(0x1d04), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x40), calldataload(0x1d24), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x60), calldataload(0x1d44), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x80), calldataload(0x1d64), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x20), calldataload(0x1c84), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x40), calldataload(0x1ca4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x60), calldataload(0x1cc4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x80), calldataload(0x1ce4), r),
            //             r
            //         )
            //         mstore(0x0640, r_eval)
            //     }
            //     {
            //         let coeff := mload(0xa0)
            //         let zeta := mload(ZETA_MPTR)
            //         let r_eval := 0
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x2ec4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), r),
            //             r
            //         )
            //         for {
            //             let mptr := 0x3504
            //             let mptr_end := 0x2ec4
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x20)
            //         } {
            //             r_eval := addmod(
            //                 mulmod(r_eval, zeta, r),
            //                 mulmod(coeff, calldataload(mptr), r),
            //                 r
            //             )
            //         }
            //         for {
            //             let mptr := 0x2ea4
            //             let mptr_end := 0x2684
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x20)
            //         } {
            //             r_eval := addmod(
            //                 mulmod(r_eval, zeta, r),
            //                 mulmod(coeff, calldataload(mptr), r),
            //                 r
            //             )
            //         }
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x4504), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x4464), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x43c4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x4324), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x4284), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x41e4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x4144), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x40a4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x4004), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x3f64), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x3ec4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x3e24), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x3d84), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x3ce4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x3c44), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x3ba4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x3b04), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x3a64), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x2684), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x2664), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x25c4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x2584), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x2564), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(coeff, calldataload(0x23e4), r),
            //             r
            //         )
            //         for {
            //             let mptr := 0x2344
            //             let mptr_end := 0x2244
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x20)
            //         } {
            //             r_eval := addmod(
            //                 mulmod(r_eval, zeta, r),
            //                 mulmod(coeff, calldataload(mptr), r),
            //                 r
            //             )
            //         }
            //         for {
            //             let mptr := 0x21c4
            //             let mptr_end := 0x2164
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x20)
            //         } {
            //             r_eval := addmod(
            //                 mulmod(r_eval, zeta, r),
            //                 mulmod(coeff, calldataload(mptr), r),
            //                 r
            //             )
            //         }
            //         r_eval := mulmod(r_eval, mload(0x05c0), r)
            //         mstore(0x0660, r_eval)
            //     }
            //     {
            //         let zeta := mload(ZETA_MPTR)
            //         let r_eval := 0
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x4484), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x44a4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x43e4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x4404), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x4344), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x4364), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x42a4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x42c4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x4204), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x4224), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x4164), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x4184), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x40c4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x40e4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x4024), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x4044), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x3f84), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x3fa4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x3ee4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x3f04), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x3e44), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x3e64), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x3da4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x3dc4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x3d04), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x3d24), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x3c64), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x3c84), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x3bc4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x3be4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x3b24), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x3b44), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x3a84), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x3aa4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x39e4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x3a04), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x39a4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x39c4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x25a4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x2644), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x2544), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x2624), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x23c4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x2524), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x23a4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x24e4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x2384), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x24a4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x2364), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x2464), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x2244), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x2504), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x2224), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x24c4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x2204), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x2484), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xc0), calldataload(0x21e4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0xe0), calldataload(0x2444), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, mload(0x05e0), r)
            //         mstore(0x0680, r_eval)
            //     }
            //     {
            //         let zeta := mload(ZETA_MPTR)
            //         let r_eval := 0
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x44e4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x44c4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x4444), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x4424), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x43a4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x4384), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x4304), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x42e4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x4264), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x4244), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x41c4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x41a4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x4124), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x4104), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x4084), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x4064), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x3fe4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x3fc4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x3f44), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x3f24), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x3ea4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x3e84), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x3e04), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x3de4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x3d64), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x3d44), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x3cc4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x3ca4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x3c24), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x3c04), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x3b84), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x3b64), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x3ae4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x3ac4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x3a44), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x3a24), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x2604), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x25e4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0100), calldataload(0x2424), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0120), calldataload(0x2404), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, mload(0x0600), r)
            //         mstore(0x06a0, r_eval)
            //     }
            //     {
            //         let zeta := mload(ZETA_MPTR)
            //         let r_eval := 0
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x3984), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x3944), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x3964), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x3924), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x38e4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x3904), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x38c4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x3884), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x38a4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x3864), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x3824), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x3844), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x3804), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x37c4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x37e4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x37a4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x3764), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x3784), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x3744), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x3704), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x3724), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x36e4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x36a4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x36c4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x3684), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x3644), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x3664), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x3624), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x35e4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x3604), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x35c4), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x3584), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x35a4), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, zeta, r)
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0140), calldataload(0x3564), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0160), calldataload(0x3524), r),
            //             r
            //         )
            //         r_eval := addmod(
            //             r_eval,
            //             mulmod(mload(0x0180), calldataload(0x3544), r),
            //             r
            //         )
            //         r_eval := mulmod(r_eval, mload(0x0620), r)
            //         mstore(0x06c0, r_eval)
            //     }
            //     {
            //         let sum := mload(0x20)
            //         sum := addmod(sum, mload(0x40), r)
            //         sum := addmod(sum, mload(0x60), r)
            //         sum := addmod(sum, mload(0x80), r)
            //         mstore(0x06e0, sum)
            //     }
            //     {
            //         let sum := mload(0xa0)
            //         mstore(0x0700, sum)
            //     }
            //     {
            //         let sum := mload(0xc0)
            //         sum := addmod(sum, mload(0xe0), r)
            //         mstore(0x0720, sum)
            //     }
            //     {
            //         let sum := mload(0x0100)
            //         sum := addmod(sum, mload(0x0120), r)
            //         mstore(0x0740, sum)
            //     }
            //     {
            //         let sum := mload(0x0140)
            //         sum := addmod(sum, mload(0x0160), r)
            //         sum := addmod(sum, mload(0x0180), r)
            //         mstore(0x0760, sum)
            //     }
            //     {
            //         for {
            //             let mptr := 0x00
            //             let mptr_end := 0xa0
            //             let sum_mptr := 0x06e0
            //         } lt(mptr, mptr_end) {
            //             mptr := add(mptr, 0x20)
            //             sum_mptr := add(sum_mptr, 0x20)
            //         } {
            //             mstore(mptr, mload(sum_mptr))
            //         }
            //         success := batch_invert(success, 0xa0, r)
            //         let r_eval := mulmod(mload(0x80), mload(0x06c0), r)
            //         for {
            //             let sum_inv_mptr := 0x60
            //             let sum_inv_mptr_end := 0xa0
            //             let r_eval_mptr := 0x06a0
            //         } lt(sum_inv_mptr, sum_inv_mptr_end) {
            //             sum_inv_mptr := sub(sum_inv_mptr, 0x20)
            //             r_eval_mptr := sub(r_eval_mptr, 0x20)
            //         } {
            //             r_eval := mulmod(r_eval, mload(NU_MPTR), r)
            //             r_eval := addmod(
            //                 r_eval,
            //                 mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), r),
            //                 r
            //             )
            //         }
            //         mstore(R_EVAL_MPTR, r_eval)
            //     }
            //     {
            //         let nu := mload(NU_MPTR)
            //         mstore(0x00, calldataload(0x02c4))
            //         mstore(0x20, calldataload(0x02e4))
            //         for {
            //             let mptr := 0x0284
            //             let mptr_end := 0x44
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x40)
            //         } {
            //             success := ec_mul_acc(success, mload(ZETA_MPTR))
            //             success := ec_add_acc(
            //                 success,
            //                 calldataload(mptr),
            //                 calldataload(add(mptr, 0x20))
            //             )
            //         }
            //         mstore(0x80, calldataload(0x1b04))
            //         mstore(0xa0, calldataload(0x1b24))
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             mload(QUOTIENT_X_MPTR),
            //             mload(QUOTIENT_Y_MPTR)
            //         )
            //         for {
            //             let mptr := 0x47e0
            //             let mptr_end := 0x2de0
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x40)
            //         } {
            //             success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //             success := ec_add_tmp(
            //                 success,
            //                 mload(mptr),
            //                 mload(add(mptr, 0x20))
            //             )
            //         }
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(success, mload(0x2b60), mload(0x2b80))
            //         for {
            //             let mptr := 0x2de0
            //             let mptr_end := 0x2b60
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x40)
            //         } {
            //             success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //             success := ec_add_tmp(
            //                 success,
            //                 mload(mptr),
            //                 mload(add(mptr, 0x20))
            //             )
            //         }
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x1304),
            //             calldataload(0x1324)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x1284),
            //             calldataload(0x12a4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x1204),
            //             calldataload(0x1224)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x1184),
            //             calldataload(0x11a4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x1104),
            //             calldataload(0x1124)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x1084),
            //             calldataload(0x10a4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x1004),
            //             calldataload(0x1024)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0f84),
            //             calldataload(0x0fa4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0f04),
            //             calldataload(0x0f24)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0e84),
            //             calldataload(0x0ea4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0e04),
            //             calldataload(0x0e24)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0d84),
            //             calldataload(0x0da4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0d04),
            //             calldataload(0x0d24)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0c84),
            //             calldataload(0x0ca4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0c04),
            //             calldataload(0x0c24)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0b84),
            //             calldataload(0x0ba4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0b04),
            //             calldataload(0x0b24)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0a84),
            //             calldataload(0x0aa4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0a04),
            //             calldataload(0x0a24)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x09c4),
            //             calldataload(0x09e4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0844),
            //             calldataload(0x0864)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0944),
            //             calldataload(0x0964)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0904),
            //             calldataload(0x0924)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x03c4),
            //             calldataload(0x03e4)
            //         )
            //         for {
            //             let mptr := 0x0704
            //             let mptr_end := 0x0504
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x40)
            //         } {
            //             success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //             success := ec_add_tmp(
            //                 success,
            //                 calldataload(mptr),
            //                 calldataload(add(mptr, 0x20))
            //             )
            //         }
            //         for {
            //             let mptr := 0x0384
            //             let mptr_end := 0x02c4
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x40)
            //         } {
            //             success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //             success := ec_add_tmp(
            //                 success,
            //                 calldataload(mptr),
            //                 calldataload(add(mptr, 0x20))
            //             )
            //         }
            //         success := ec_mul_tmp(success, mulmod(nu, mload(0x05c0), r))
            //         success := ec_add_acc(success, mload(0x80), mload(0xa0))
            //         nu := mulmod(nu, mload(NU_MPTR), r)
            //         mstore(0x80, calldataload(0x1ac4))
            //         mstore(0xa0, calldataload(0x1ae4))
            //         for {
            //             let mptr := 0x1a84
            //             let mptr_end := 0x1604
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x40)
            //         } {
            //             success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //             success := ec_add_tmp(
            //                 success,
            //                 calldataload(mptr),
            //                 calldataload(add(mptr, 0x20))
            //             )
            //         }
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0984),
            //             calldataload(0x09a4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x08c4),
            //             calldataload(0x08e4)
            //         )
            //         for {
            //             let mptr := 0x0804
            //             let mptr_end := 0x0704
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x40)
            //         } {
            //             success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //             success := ec_add_tmp(
            //                 success,
            //                 calldataload(mptr),
            //                 calldataload(add(mptr, 0x20))
            //             )
            //         }
            //         for {
            //             let mptr := 0x0504
            //             let mptr_end := 0x0404
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x40)
            //         } {
            //             success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //             success := ec_add_tmp(
            //                 success,
            //                 calldataload(mptr),
            //                 calldataload(add(mptr, 0x20))
            //             )
            //         }
            //         success := ec_mul_tmp(success, mulmod(nu, mload(0x05e0), r))
            //         success := ec_add_acc(success, mload(0x80), mload(0xa0))
            //         nu := mulmod(nu, mload(NU_MPTR), r)
            //         mstore(0x80, calldataload(0x12c4))
            //         mstore(0xa0, calldataload(0x12e4))
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x1244),
            //             calldataload(0x1264)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x11c4),
            //             calldataload(0x11e4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x1144),
            //             calldataload(0x1164)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x10c4),
            //             calldataload(0x10e4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x1044),
            //             calldataload(0x1064)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0fc4),
            //             calldataload(0x0fe4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0f44),
            //             calldataload(0x0f64)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0ec4),
            //             calldataload(0x0ee4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0e44),
            //             calldataload(0x0e64)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0dc4),
            //             calldataload(0x0de4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0d44),
            //             calldataload(0x0d64)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0cc4),
            //             calldataload(0x0ce4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0c44),
            //             calldataload(0x0c64)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0bc4),
            //             calldataload(0x0be4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0b44),
            //             calldataload(0x0b64)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0ac4),
            //             calldataload(0x0ae4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0a44),
            //             calldataload(0x0a64)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0884),
            //             calldataload(0x08a4)
            //         )
            //         success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //         success := ec_add_tmp(
            //             success,
            //             calldataload(0x0404),
            //             calldataload(0x0424)
            //         )
            //         success := ec_mul_tmp(success, mulmod(nu, mload(0x0600), r))
            //         success := ec_add_acc(success, mload(0x80), mload(0xa0))
            //         nu := mulmod(nu, mload(NU_MPTR), r)
            //         mstore(0x80, calldataload(0x1604))
            //         mstore(0xa0, calldataload(0x1624))
            //         for {
            //             let mptr := 0x15c4
            //             let mptr_end := 0x1304
            //         } lt(mptr_end, mptr) {
            //             mptr := sub(mptr, 0x40)
            //         } {
            //             success := ec_mul_tmp(success, mload(ZETA_MPTR))
            //             success := ec_add_tmp(
            //                 success,
            //                 calldataload(mptr),
            //                 calldataload(add(mptr, 0x20))
            //             )
            //         }
            //         success := ec_mul_tmp(success, mulmod(nu, mload(0x0620), r))
            //         success := ec_add_acc(success, mload(0x80), mload(0xa0))
            //         mstore(0x80, mload(G1_X_MPTR))
            //         mstore(0xa0, mload(G1_Y_MPTR))
            //         success := ec_mul_tmp(success, sub(r, mload(R_EVAL_MPTR)))
            //         success := ec_add_acc(success, mload(0x80), mload(0xa0))
            //         mstore(0x80, calldataload(0x4524))
            //         mstore(0xa0, calldataload(0x4544))
            //         success := ec_mul_tmp(success, sub(r, mload(0x0580)))
            //         success := ec_add_acc(success, mload(0x80), mload(0xa0))
            //         mstore(0x80, calldataload(0x4564))
            //         mstore(0xa0, calldataload(0x4584))
            //         success := ec_mul_tmp(success, mload(MU_MPTR))
            //         success := ec_add_acc(success, mload(0x80), mload(0xa0))
            //         mstore(PAIRING_LHS_X_MPTR, mload(0x00))
            //         mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
            //         mstore(PAIRING_RHS_X_MPTR, calldataload(0x4564))
            //         mstore(PAIRING_RHS_Y_MPTR, calldataload(0x4584))
            //     }
            // }

            // Random linear combine with accumulator
            // if mload(HAS_ACCUMULATOR_MPTR) {
            //     mstore(0x00, mload(ACC_LHS_X_MPTR))
            //     mstore(0x20, mload(ACC_LHS_Y_MPTR))
            //     mstore(0x40, mload(ACC_RHS_X_MPTR))
            //     mstore(0x60, mload(ACC_RHS_Y_MPTR))
            //     mstore(0x80, mload(PAIRING_LHS_X_MPTR))
            //     mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
            //     mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
            //     mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
            //     let challenge := mod(keccak256(0x00, 0x100), r)

            //     // [pairing_lhs] += challenge * [acc_lhs]
            //     success := ec_mul_acc(success, challenge)
            //     success := ec_add_acc(
            //         success,
            //         mload(PAIRING_LHS_X_MPTR),
            //         mload(PAIRING_LHS_Y_MPTR)
            //     )
            //     mstore(PAIRING_LHS_X_MPTR, mload(0x00))
            //     mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

            //     // [pairing_rhs] += challenge * [acc_rhs]
            //     mstore(0x00, mload(ACC_RHS_X_MPTR))
            //     mstore(0x20, mload(ACC_RHS_Y_MPTR))
            //     success := ec_mul_acc(success, challenge)
            //     success := ec_add_acc(
            //         success,
            //         mload(PAIRING_RHS_X_MPTR),
            //         mload(PAIRING_RHS_Y_MPTR)
            //     )
            //     mstore(PAIRING_RHS_X_MPTR, mload(0x00))
            //     mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            // }

            // Perform pairing
            // success := ec_pairing(
            //     success,
            //     mload(PAIRING_LHS_X_MPTR),
            //     mload(PAIRING_LHS_Y_MPTR),
            //     mload(PAIRING_RHS_X_MPTR),
            //     mload(PAIRING_RHS_Y_MPTR)
            // )

            // Revert if anything fails,
            // if iszero(success) {
            //     revert(0x00, 0x00)
            // }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}
