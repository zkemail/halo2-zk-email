// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "../VerifierFuncAbst.sol";

contract VerifierFunc0 is VerifierFuncAbst {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes32[] memory _transcript
    ) public view override returns (bool, bytes32[] memory) {
        bytes32[2776] memory transcript;
        for(uint i=0; i<_transcript.length; i++) {
            transcript[i] = _transcript[i];
        }
        assembly {{
                                let f_p := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    let f_q := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    function validate_ec_point(x, y) -> valid {
                        {                            let x_lt_p := lt(x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)                            let y_lt_p := lt(y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)                            valid := and(x_lt_p, y_lt_p)                        }
                        {                            let x_is_zero := eq(x, 0)                            let y_is_zero := eq(y, 0)                            let x_or_y_is_zero := or(x_is_zero, y_is_zero)                            let x_and_y_is_not_zero := not(x_or_y_is_zero)                            valid := and(x_and_y_is_not_zero, valid)                        }
                        {                            let y_square := mulmod(y, y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)                            let x_square := mulmod(x, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)                            let x_cube := mulmod(x_square, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)                            let x_cube_plus_3 := addmod(x_cube, 3, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)                            let y_square_eq_x_cube_plus_3 := eq(x_cube_plus_3, y_square)                            valid := and(y_square_eq_x_cube_plus_3, valid)                        }
                    }
                    mstore(add(transcript, 0x20), mod(mload(add(pubInputs, 0x20)), f_q))
mstore(add(transcript, 0x40), mod(mload(add(pubInputs, 0x40)), f_q))
mstore(add(transcript, 0x60), mod(mload(add(pubInputs, 0x60)), f_q))
mstore(add(transcript, 0x0), 5272874504912817135692230416725035005751154424620296571435877469615512831695)

        {            let x := mload(add(proof, 0x20))            mstore(add(transcript, 0x80), x)            let y := mload(add(proof, 0x40))            mstore(add(transcript, 0xa0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x60))            mstore(add(transcript, 0xc0), x)            let y := mload(add(proof, 0x80))            mstore(add(transcript, 0xe0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xa0))            mstore(add(transcript, 0x100), x)            let y := mload(add(proof, 0xc0))            mstore(add(transcript, 0x120), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xe0))            mstore(add(transcript, 0x140), x)            let y := mload(add(proof, 0x100))            mstore(add(transcript, 0x160), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x120))            mstore(add(transcript, 0x180), x)            let y := mload(add(proof, 0x140))            mstore(add(transcript, 0x1a0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x160))            mstore(add(transcript, 0x1c0), x)            let y := mload(add(proof, 0x180))            mstore(add(transcript, 0x1e0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1a0))            mstore(add(transcript, 0x200), x)            let y := mload(add(proof, 0x1c0))            mstore(add(transcript, 0x220), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1e0))            mstore(add(transcript, 0x240), x)            let y := mload(add(proof, 0x200))            mstore(add(transcript, 0x260), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x220))            mstore(add(transcript, 0x280), x)            let y := mload(add(proof, 0x240))            mstore(add(transcript, 0x2a0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x260))            mstore(add(transcript, 0x2c0), x)            let y := mload(add(proof, 0x280))            mstore(add(transcript, 0x2e0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2a0))            mstore(add(transcript, 0x300), x)            let y := mload(add(proof, 0x2c0))            mstore(add(transcript, 0x320), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2e0))            mstore(add(transcript, 0x340), x)            let y := mload(add(proof, 0x300))            mstore(add(transcript, 0x360), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x320))            mstore(add(transcript, 0x380), x)            let y := mload(add(proof, 0x340))            mstore(add(transcript, 0x3a0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x360))            mstore(add(transcript, 0x3c0), x)            let y := mload(add(proof, 0x380))            mstore(add(transcript, 0x3e0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x3a0))            mstore(add(transcript, 0x400), x)            let y := mload(add(proof, 0x3c0))            mstore(add(transcript, 0x420), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x3e0))            mstore(add(transcript, 0x440), x)            let y := mload(add(proof, 0x400))            mstore(add(transcript, 0x460), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x420))            mstore(add(transcript, 0x480), x)            let y := mload(add(proof, 0x440))            mstore(add(transcript, 0x4a0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x460))            mstore(add(transcript, 0x4c0), x)            let y := mload(add(proof, 0x480))            mstore(add(transcript, 0x4e0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x4a0))            mstore(add(transcript, 0x500), x)            let y := mload(add(proof, 0x4c0))            mstore(add(transcript, 0x520), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x4e0))            mstore(add(transcript, 0x540), x)            let y := mload(add(proof, 0x500))            mstore(add(transcript, 0x560), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x520))            mstore(add(transcript, 0x580), x)            let y := mload(add(proof, 0x540))            mstore(add(transcript, 0x5a0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x560))            mstore(add(transcript, 0x5c0), x)            let y := mload(add(proof, 0x580))            mstore(add(transcript, 0x5e0), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0x600), keccak256(add(transcript, 0x0), 1536))
{            let hash := mload(add(transcript, 0x600))            mstore(add(transcript, 0x620), mod(hash, f_q))            mstore(add(transcript, 0x640), hash)        }

        {            let x := mload(add(proof, 0x5a0))            mstore(add(transcript, 0x660), x)            let y := mload(add(proof, 0x5c0))            mstore(add(transcript, 0x680), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x5e0))            mstore(add(transcript, 0x6a0), x)            let y := mload(add(proof, 0x600))            mstore(add(transcript, 0x6c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x620))            mstore(add(transcript, 0x6e0), x)            let y := mload(add(proof, 0x640))            mstore(add(transcript, 0x700), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x660))            mstore(add(transcript, 0x720), x)            let y := mload(add(proof, 0x680))            mstore(add(transcript, 0x740), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x6a0))            mstore(add(transcript, 0x760), x)            let y := mload(add(proof, 0x6c0))            mstore(add(transcript, 0x780), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x6e0))            mstore(add(transcript, 0x7a0), x)            let y := mload(add(proof, 0x700))            mstore(add(transcript, 0x7c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x720))            mstore(add(transcript, 0x7e0), x)            let y := mload(add(proof, 0x740))            mstore(add(transcript, 0x800), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x760))            mstore(add(transcript, 0x820), x)            let y := mload(add(proof, 0x780))            mstore(add(transcript, 0x840), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x7a0))            mstore(add(transcript, 0x860), x)            let y := mload(add(proof, 0x7c0))            mstore(add(transcript, 0x880), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x7e0))            mstore(add(transcript, 0x8a0), x)            let y := mload(add(proof, 0x800))            mstore(add(transcript, 0x8c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x820))            mstore(add(transcript, 0x8e0), x)            let y := mload(add(proof, 0x840))            mstore(add(transcript, 0x900), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x860))            mstore(add(transcript, 0x920), x)            let y := mload(add(proof, 0x880))            mstore(add(transcript, 0x940), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x8a0))            mstore(add(transcript, 0x960), x)            let y := mload(add(proof, 0x8c0))            mstore(add(transcript, 0x980), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x8e0))            mstore(add(transcript, 0x9a0), x)            let y := mload(add(proof, 0x900))            mstore(add(transcript, 0x9c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x920))            mstore(add(transcript, 0x9e0), x)            let y := mload(add(proof, 0x940))            mstore(add(transcript, 0xa00), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x960))            mstore(add(transcript, 0xa20), x)            let y := mload(add(proof, 0x980))            mstore(add(transcript, 0xa40), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x9a0))            mstore(add(transcript, 0xa60), x)            let y := mload(add(proof, 0x9c0))            mstore(add(transcript, 0xa80), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x9e0))            mstore(add(transcript, 0xaa0), x)            let y := mload(add(proof, 0xa00))            mstore(add(transcript, 0xac0), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0xae0), keccak256(add(transcript, 0x640), 1184))
{            let hash := mload(add(transcript, 0xae0))            mstore(add(transcript, 0xb00), mod(hash, f_q))            mstore(add(transcript, 0xb20), hash)        }
mstore8(add(transcript, 0xb40), 1)
mstore(add(transcript, 0xb40), keccak256(add(transcript, 0xb20), 33))
{            let hash := mload(add(transcript, 0xb40))            mstore(add(transcript, 0xb60), mod(hash, f_q))            mstore(add(transcript, 0xb80), hash)        }

        {            let x := mload(add(proof, 0xa20))            mstore(add(transcript, 0xba0), x)            let y := mload(add(proof, 0xa40))            mstore(add(transcript, 0xbc0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xa60))            mstore(add(transcript, 0xbe0), x)            let y := mload(add(proof, 0xa80))            mstore(add(transcript, 0xc00), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xaa0))            mstore(add(transcript, 0xc20), x)            let y := mload(add(proof, 0xac0))            mstore(add(transcript, 0xc40), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xae0))            mstore(add(transcript, 0xc60), x)            let y := mload(add(proof, 0xb00))            mstore(add(transcript, 0xc80), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xb20))            mstore(add(transcript, 0xca0), x)            let y := mload(add(proof, 0xb40))            mstore(add(transcript, 0xcc0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xb60))            mstore(add(transcript, 0xce0), x)            let y := mload(add(proof, 0xb80))            mstore(add(transcript, 0xd00), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xba0))            mstore(add(transcript, 0xd20), x)            let y := mload(add(proof, 0xbc0))            mstore(add(transcript, 0xd40), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xbe0))            mstore(add(transcript, 0xd60), x)            let y := mload(add(proof, 0xc00))            mstore(add(transcript, 0xd80), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xc20))            mstore(add(transcript, 0xda0), x)            let y := mload(add(proof, 0xc40))            mstore(add(transcript, 0xdc0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xc60))            mstore(add(transcript, 0xde0), x)            let y := mload(add(proof, 0xc80))            mstore(add(transcript, 0xe00), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xca0))            mstore(add(transcript, 0xe20), x)            let y := mload(add(proof, 0xcc0))            mstore(add(transcript, 0xe40), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xce0))            mstore(add(transcript, 0xe60), x)            let y := mload(add(proof, 0xd00))            mstore(add(transcript, 0xe80), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xd20))            mstore(add(transcript, 0xea0), x)            let y := mload(add(proof, 0xd40))            mstore(add(transcript, 0xec0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xd60))            mstore(add(transcript, 0xee0), x)            let y := mload(add(proof, 0xd80))            mstore(add(transcript, 0xf00), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xda0))            mstore(add(transcript, 0xf20), x)            let y := mload(add(proof, 0xdc0))            mstore(add(transcript, 0xf40), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xde0))            mstore(add(transcript, 0xf60), x)            let y := mload(add(proof, 0xe00))            mstore(add(transcript, 0xf80), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0xfa0), keccak256(add(transcript, 0xb80), 1056))
{            let hash := mload(add(transcript, 0xfa0))            mstore(add(transcript, 0xfc0), mod(hash, f_q))            mstore(add(transcript, 0xfe0), hash)        }

        {            let x := mload(add(proof, 0xe20))            mstore(add(transcript, 0x1000), x)            let y := mload(add(proof, 0xe40))            mstore(add(transcript, 0x1020), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xe60))            mstore(add(transcript, 0x1040), x)            let y := mload(add(proof, 0xe80))            mstore(add(transcript, 0x1060), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xea0))            mstore(add(transcript, 0x1080), x)            let y := mload(add(proof, 0xec0))            mstore(add(transcript, 0x10a0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xee0))            mstore(add(transcript, 0x10c0), x)            let y := mload(add(proof, 0xf00))            mstore(add(transcript, 0x10e0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xf20))            mstore(add(transcript, 0x1100), x)            let y := mload(add(proof, 0xf40))            mstore(add(transcript, 0x1120), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0x1140), keccak256(add(transcript, 0xfe0), 352))
{            let hash := mload(add(transcript, 0x1140))            mstore(add(transcript, 0x1160), mod(hash, f_q))            mstore(add(transcript, 0x1180), hash)        }
mstore(add(transcript, 0x11a0), mod(mload(add(proof, 0xf60)), f_q))
mstore(add(transcript, 0x11c0), mod(mload(add(proof, 0xf80)), f_q))
mstore(add(transcript, 0x11e0), mod(mload(add(proof, 0xfa0)), f_q))
mstore(add(transcript, 0x1200), mod(mload(add(proof, 0xfc0)), f_q))
mstore(add(transcript, 0x1220), mod(mload(add(proof, 0xfe0)), f_q))
mstore(add(transcript, 0x1240), mod(mload(add(proof, 0x1000)), f_q))
mstore(add(transcript, 0x1260), mod(mload(add(proof, 0x1020)), f_q))
mstore(add(transcript, 0x1280), mod(mload(add(proof, 0x1040)), f_q))
mstore(add(transcript, 0x12a0), mod(mload(add(proof, 0x1060)), f_q))
mstore(add(transcript, 0x12c0), mod(mload(add(proof, 0x1080)), f_q))
mstore(add(transcript, 0x12e0), mod(mload(add(proof, 0x10a0)), f_q))
mstore(add(transcript, 0x1300), mod(mload(add(proof, 0x10c0)), f_q))
mstore(add(transcript, 0x1320), mod(mload(add(proof, 0x10e0)), f_q))
mstore(add(transcript, 0x1340), mod(mload(add(proof, 0x1100)), f_q))
mstore(add(transcript, 0x1360), mod(mload(add(proof, 0x1120)), f_q))
mstore(add(transcript, 0x1380), mod(mload(add(proof, 0x1140)), f_q))
mstore(add(transcript, 0x13a0), mod(mload(add(proof, 0x1160)), f_q))
mstore(add(transcript, 0x13c0), mod(mload(add(proof, 0x1180)), f_q))
mstore(add(transcript, 0x13e0), mod(mload(add(proof, 0x11a0)), f_q))
mstore(add(transcript, 0x1400), mod(mload(add(proof, 0x11c0)), f_q))
mstore(add(transcript, 0x1420), mod(mload(add(proof, 0x11e0)), f_q))
mstore(add(transcript, 0x1440), mod(mload(add(proof, 0x1200)), f_q))
mstore(add(transcript, 0x1460), mod(mload(add(proof, 0x1220)), f_q))
mstore(add(transcript, 0x1480), mod(mload(add(proof, 0x1240)), f_q))
mstore(add(transcript, 0x14a0), mod(mload(add(proof, 0x1260)), f_q))
mstore(add(transcript, 0x14c0), mod(mload(add(proof, 0x1280)), f_q))
mstore(add(transcript, 0x14e0), mod(mload(add(proof, 0x12a0)), f_q))
mstore(add(transcript, 0x1500), mod(mload(add(proof, 0x12c0)), f_q))
mstore(add(transcript, 0x1520), mod(mload(add(proof, 0x12e0)), f_q))
mstore(add(transcript, 0x1540), mod(mload(add(proof, 0x1300)), f_q))
mstore(add(transcript, 0x1560), mod(mload(add(proof, 0x1320)), f_q))
mstore(add(transcript, 0x1580), mod(mload(add(proof, 0x1340)), f_q))
mstore(add(transcript, 0x15a0), mod(mload(add(proof, 0x1360)), f_q))
mstore(add(transcript, 0x15c0), mod(mload(add(proof, 0x1380)), f_q))
mstore(add(transcript, 0x15e0), mod(mload(add(proof, 0x13a0)), f_q))
mstore(add(transcript, 0x1600), mod(mload(add(proof, 0x13c0)), f_q))
mstore(add(transcript, 0x1620), mod(mload(add(proof, 0x13e0)), f_q))
mstore(add(transcript, 0x1640), mod(mload(add(proof, 0x1400)), f_q))
mstore(add(transcript, 0x1660), mod(mload(add(proof, 0x1420)), f_q))
mstore(add(transcript, 0x1680), mod(mload(add(proof, 0x1440)), f_q))
mstore(add(transcript, 0x16a0), mod(mload(add(proof, 0x1460)), f_q))
mstore(add(transcript, 0x16c0), mod(mload(add(proof, 0x1480)), f_q))
mstore(add(transcript, 0x16e0), mod(mload(add(proof, 0x14a0)), f_q))
mstore(add(transcript, 0x1700), mod(mload(add(proof, 0x14c0)), f_q))
mstore(add(transcript, 0x1720), mod(mload(add(proof, 0x14e0)), f_q))
mstore(add(transcript, 0x1740), mod(mload(add(proof, 0x1500)), f_q))
mstore(add(transcript, 0x1760), mod(mload(add(proof, 0x1520)), f_q))
mstore(add(transcript, 0x1780), mod(mload(add(proof, 0x1540)), f_q))
mstore(add(transcript, 0x17a0), mod(mload(add(proof, 0x1560)), f_q))
mstore(add(transcript, 0x17c0), mod(mload(add(proof, 0x1580)), f_q))
mstore(add(transcript, 0x17e0), mod(mload(add(proof, 0x15a0)), f_q))
mstore(add(transcript, 0x1800), mod(mload(add(proof, 0x15c0)), f_q))
mstore(add(transcript, 0x1820), mod(mload(add(proof, 0x15e0)), f_q))
mstore(add(transcript, 0x1840), mod(mload(add(proof, 0x1600)), f_q))
mstore(add(transcript, 0x1860), mod(mload(add(proof, 0x1620)), f_q))
mstore(add(transcript, 0x1880), mod(mload(add(proof, 0x1640)), f_q))
mstore(add(transcript, 0x18a0), mod(mload(add(proof, 0x1660)), f_q))
mstore(add(transcript, 0x18c0), mod(mload(add(proof, 0x1680)), f_q))
mstore(add(transcript, 0x18e0), mod(mload(add(proof, 0x16a0)), f_q))
mstore(add(transcript, 0x1900), mod(mload(add(proof, 0x16c0)), f_q))
mstore(add(transcript, 0x1920), mod(mload(add(proof, 0x16e0)), f_q))
mstore(add(transcript, 0x1940), mod(mload(add(proof, 0x1700)), f_q))
mstore(add(transcript, 0x1960), mod(mload(add(proof, 0x1720)), f_q))
mstore(add(transcript, 0x1980), mod(mload(add(proof, 0x1740)), f_q))
mstore(add(transcript, 0x19a0), mod(mload(add(proof, 0x1760)), f_q))
mstore(add(transcript, 0x19c0), mod(mload(add(proof, 0x1780)), f_q))
mstore(add(transcript, 0x19e0), mod(mload(add(proof, 0x17a0)), f_q))
mstore(add(transcript, 0x1a00), mod(mload(add(proof, 0x17c0)), f_q))
mstore(add(transcript, 0x1a20), mod(mload(add(proof, 0x17e0)), f_q))
mstore(add(transcript, 0x1a40), mod(mload(add(proof, 0x1800)), f_q))
mstore(add(transcript, 0x1a60), mod(mload(add(proof, 0x1820)), f_q))
mstore(add(transcript, 0x1a80), mod(mload(add(proof, 0x1840)), f_q))
mstore(add(transcript, 0x1aa0), mod(mload(add(proof, 0x1860)), f_q))
mstore(add(transcript, 0x1ac0), mod(mload(add(proof, 0x1880)), f_q))
mstore(add(transcript, 0x1ae0), mod(mload(add(proof, 0x18a0)), f_q))
mstore(add(transcript, 0x1b00), mod(mload(add(proof, 0x18c0)), f_q))
mstore(add(transcript, 0x1b20), mod(mload(add(proof, 0x18e0)), f_q))
mstore(add(transcript, 0x1b40), mod(mload(add(proof, 0x1900)), f_q))
mstore(add(transcript, 0x1b60), mod(mload(add(proof, 0x1920)), f_q))
mstore(add(transcript, 0x1b80), mod(mload(add(proof, 0x1940)), f_q))
mstore(add(transcript, 0x1ba0), mod(mload(add(proof, 0x1960)), f_q))
mstore(add(transcript, 0x1bc0), mod(mload(add(proof, 0x1980)), f_q))
mstore(add(transcript, 0x1be0), mod(mload(add(proof, 0x19a0)), f_q))
mstore(add(transcript, 0x1c00), mod(mload(add(proof, 0x19c0)), f_q))
mstore(add(transcript, 0x1c20), mod(mload(add(proof, 0x19e0)), f_q))
mstore(add(transcript, 0x1c40), mod(mload(add(proof, 0x1a00)), f_q))
mstore(add(transcript, 0x1c60), mod(mload(add(proof, 0x1a20)), f_q))
mstore(add(transcript, 0x1c80), mod(mload(add(proof, 0x1a40)), f_q))
mstore(add(transcript, 0x1ca0), mod(mload(add(proof, 0x1a60)), f_q))
mstore(add(transcript, 0x1cc0), mod(mload(add(proof, 0x1a80)), f_q))
mstore(add(transcript, 0x1ce0), mod(mload(add(proof, 0x1aa0)), f_q))
mstore(add(transcript, 0x1d00), mod(mload(add(proof, 0x1ac0)), f_q))
mstore(add(transcript, 0x1d20), mod(mload(add(proof, 0x1ae0)), f_q))
mstore(add(transcript, 0x1d40), mod(mload(add(proof, 0x1b00)), f_q))
mstore(add(transcript, 0x1d60), mod(mload(add(proof, 0x1b20)), f_q))
mstore(add(transcript, 0x1d80), mod(mload(add(proof, 0x1b40)), f_q))
mstore(add(transcript, 0x1da0), mod(mload(add(proof, 0x1b60)), f_q))
mstore(add(transcript, 0x1dc0), mod(mload(add(proof, 0x1b80)), f_q))
mstore(add(transcript, 0x1de0), mod(mload(add(proof, 0x1ba0)), f_q))
mstore(add(transcript, 0x1e00), mod(mload(add(proof, 0x1bc0)), f_q))
mstore(add(transcript, 0x1e20), mod(mload(add(proof, 0x1be0)), f_q))
mstore(add(transcript, 0x1e40), mod(mload(add(proof, 0x1c00)), f_q))
mstore(add(transcript, 0x1e60), mod(mload(add(proof, 0x1c20)), f_q))
mstore(add(transcript, 0x1e80), mod(mload(add(proof, 0x1c40)), f_q))
mstore(add(transcript, 0x1ea0), mod(mload(add(proof, 0x1c60)), f_q))
mstore(add(transcript, 0x1ec0), mod(mload(add(proof, 0x1c80)), f_q))
mstore(add(transcript, 0x1ee0), mod(mload(add(proof, 0x1ca0)), f_q))
mstore(add(transcript, 0x1f00), mod(mload(add(proof, 0x1cc0)), f_q))
mstore(add(transcript, 0x1f20), mod(mload(add(proof, 0x1ce0)), f_q))
mstore(add(transcript, 0x1f40), mod(mload(add(proof, 0x1d00)), f_q))
mstore(add(transcript, 0x1f60), mod(mload(add(proof, 0x1d20)), f_q))
mstore(add(transcript, 0x1f80), mod(mload(add(proof, 0x1d40)), f_q))
mstore(add(transcript, 0x1fa0), mod(mload(add(proof, 0x1d60)), f_q))
mstore(add(transcript, 0x1fc0), mod(mload(add(proof, 0x1d80)), f_q))
mstore(add(transcript, 0x1fe0), mod(mload(add(proof, 0x1da0)), f_q))
mstore(add(transcript, 0x2000), mod(mload(add(proof, 0x1dc0)), f_q))
mstore(add(transcript, 0x2020), mod(mload(add(proof, 0x1de0)), f_q))
mstore(add(transcript, 0x2040), mod(mload(add(proof, 0x1e00)), f_q))
mstore(add(transcript, 0x2060), mod(mload(add(proof, 0x1e20)), f_q))
mstore(add(transcript, 0x2080), mod(mload(add(proof, 0x1e40)), f_q))
mstore(add(transcript, 0x20a0), mod(mload(add(proof, 0x1e60)), f_q))
mstore(add(transcript, 0x20c0), mod(mload(add(proof, 0x1e80)), f_q))
mstore(add(transcript, 0x20e0), mod(mload(add(proof, 0x1ea0)), f_q))
mstore(add(transcript, 0x2100), mod(mload(add(proof, 0x1ec0)), f_q))
mstore(add(transcript, 0x2120), mod(mload(add(proof, 0x1ee0)), f_q))
mstore(add(transcript, 0x2140), mod(mload(add(proof, 0x1f00)), f_q))
mstore(add(transcript, 0x2160), mod(mload(add(proof, 0x1f20)), f_q))
mstore(add(transcript, 0x2180), mod(mload(add(proof, 0x1f40)), f_q))
mstore(add(transcript, 0x21a0), mod(mload(add(proof, 0x1f60)), f_q))
mstore(add(transcript, 0x21c0), mod(mload(add(proof, 0x1f80)), f_q))
mstore(add(transcript, 0x21e0), mod(mload(add(proof, 0x1fa0)), f_q))
mstore(add(transcript, 0x2200), mod(mload(add(proof, 0x1fc0)), f_q))
mstore(add(transcript, 0x2220), mod(mload(add(proof, 0x1fe0)), f_q))
mstore(add(transcript, 0x2240), mod(mload(add(proof, 0x2000)), f_q))
mstore(add(transcript, 0x2260), mod(mload(add(proof, 0x2020)), f_q))
mstore(add(transcript, 0x2280), mod(mload(add(proof, 0x2040)), f_q))
mstore(add(transcript, 0x22a0), mod(mload(add(proof, 0x2060)), f_q))
mstore(add(transcript, 0x22c0), mod(mload(add(proof, 0x2080)), f_q))
mstore(add(transcript, 0x22e0), mod(mload(add(proof, 0x20a0)), f_q))
mstore(add(transcript, 0x2300), mod(mload(add(proof, 0x20c0)), f_q))
mstore(add(transcript, 0x2320), mod(mload(add(proof, 0x20e0)), f_q))
mstore(add(transcript, 0x2340), mod(mload(add(proof, 0x2100)), f_q))
mstore(add(transcript, 0x2360), mod(mload(add(proof, 0x2120)), f_q))
mstore(add(transcript, 0x2380), mod(mload(add(proof, 0x2140)), f_q))
mstore(add(transcript, 0x23a0), mod(mload(add(proof, 0x2160)), f_q))
mstore(add(transcript, 0x23c0), mod(mload(add(proof, 0x2180)), f_q))
mstore(add(transcript, 0x23e0), mod(mload(add(proof, 0x21a0)), f_q))
mstore(add(transcript, 0x2400), mod(mload(add(proof, 0x21c0)), f_q))
mstore(add(transcript, 0x2420), mod(mload(add(proof, 0x21e0)), f_q))
mstore(add(transcript, 0x2440), mod(mload(add(proof, 0x2200)), f_q))
mstore(add(transcript, 0x2460), mod(mload(add(proof, 0x2220)), f_q))
mstore(add(transcript, 0x2480), mod(mload(add(proof, 0x2240)), f_q))
mstore(add(transcript, 0x24a0), mod(mload(add(proof, 0x2260)), f_q))
mstore(add(transcript, 0x24c0), mod(mload(add(proof, 0x2280)), f_q))
mstore(add(transcript, 0x24e0), mod(mload(add(proof, 0x22a0)), f_q))
mstore(add(transcript, 0x2500), mod(mload(add(proof, 0x22c0)), f_q))
mstore(add(transcript, 0x2520), mod(mload(add(proof, 0x22e0)), f_q))
mstore(add(transcript, 0x2540), mod(mload(add(proof, 0x2300)), f_q))
mstore(add(transcript, 0x2560), mod(mload(add(proof, 0x2320)), f_q))
mstore(add(transcript, 0x2580), mod(mload(add(proof, 0x2340)), f_q))
mstore(add(transcript, 0x25a0), mod(mload(add(proof, 0x2360)), f_q))
mstore(add(transcript, 0x25c0), mod(mload(add(proof, 0x2380)), f_q))
mstore(add(transcript, 0x25e0), mod(mload(add(proof, 0x23a0)), f_q))
mstore(add(transcript, 0x2600), mod(mload(add(proof, 0x23c0)), f_q))
mstore(add(transcript, 0x2620), mod(mload(add(proof, 0x23e0)), f_q))
mstore(add(transcript, 0x2640), mod(mload(add(proof, 0x2400)), f_q))
mstore(add(transcript, 0x2660), mod(mload(add(proof, 0x2420)), f_q))
mstore(add(transcript, 0x2680), keccak256(add(transcript, 0x1180), 5376))
{            let hash := mload(add(transcript, 0x2680))            mstore(add(transcript, 0x26a0), mod(hash, f_q))            mstore(add(transcript, 0x26c0), hash)        }
mstore8(add(transcript, 0x26e0), 1)
mstore(add(transcript, 0x26e0), keccak256(add(transcript, 0x26c0), 33))
{            let hash := mload(add(transcript, 0x26e0))            mstore(add(transcript, 0x2700), mod(hash, f_q))            mstore(add(transcript, 0x2720), hash)        }

        {            let x := mload(add(proof, 0x2440))            mstore(add(transcript, 0x2740), x)            let y := mload(add(proof, 0x2460))            mstore(add(transcript, 0x2760), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0x2780), keccak256(add(transcript, 0x2720), 96))
{            let hash := mload(add(transcript, 0x2780))            mstore(add(transcript, 0x27a0), mod(hash, f_q))            mstore(add(transcript, 0x27c0), hash)        }

        {            let x := mload(add(proof, 0x2480))            mstore(add(transcript, 0x27e0), x)            let y := mload(add(proof, 0x24a0))            mstore(add(transcript, 0x2800), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0x2820), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x1160)), f_q))
mstore(add(transcript, 0x2840), mulmod(mload(add(transcript, 0x2820)), mload(add(transcript, 0x2820)), f_q))
mstore(add(transcript, 0x2860), mulmod(mload(add(transcript, 0x2840)), mload(add(transcript, 0x2840)), f_q))
mstore(add(transcript, 0x2880), mulmod(mload(add(transcript, 0x2860)), mload(add(transcript, 0x2860)), f_q))
mstore(add(transcript, 0x28a0), mulmod(mload(add(transcript, 0x2880)), mload(add(transcript, 0x2880)), f_q))
mstore(add(transcript, 0x28c0), mulmod(mload(add(transcript, 0x28a0)), mload(add(transcript, 0x28a0)), f_q))
mstore(add(transcript, 0x28e0), mulmod(mload(add(transcript, 0x28c0)), mload(add(transcript, 0x28c0)), f_q))
mstore(add(transcript, 0x2900), mulmod(mload(add(transcript, 0x28e0)), mload(add(transcript, 0x28e0)), f_q))
mstore(add(transcript, 0x2920), mulmod(mload(add(transcript, 0x2900)), mload(add(transcript, 0x2900)), f_q))
mstore(add(transcript, 0x2940), mulmod(mload(add(transcript, 0x2920)), mload(add(transcript, 0x2920)), f_q))
mstore(add(transcript, 0x2960), mulmod(mload(add(transcript, 0x2940)), mload(add(transcript, 0x2940)), f_q))
mstore(add(transcript, 0x2980), mulmod(mload(add(transcript, 0x2960)), mload(add(transcript, 0x2960)), f_q))
mstore(add(transcript, 0x29a0), mulmod(mload(add(transcript, 0x2980)), mload(add(transcript, 0x2980)), f_q))
mstore(add(transcript, 0x29c0), mulmod(mload(add(transcript, 0x29a0)), mload(add(transcript, 0x29a0)), f_q))
mstore(add(transcript, 0x29e0), mulmod(mload(add(transcript, 0x29c0)), mload(add(transcript, 0x29c0)), f_q))
mstore(add(transcript, 0x2a00), mulmod(mload(add(transcript, 0x29e0)), mload(add(transcript, 0x29e0)), f_q))
mstore(add(transcript, 0x2a20), mulmod(mload(add(transcript, 0x2a00)), mload(add(transcript, 0x2a00)), f_q))
mstore(add(transcript, 0x2a40), addmod(mload(add(transcript, 0x2a20)), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q))
mstore(add(transcript, 0x2a60), mulmod(mload(add(transcript, 0x2a40)), 21888075877798810139885396174900942254113179552665176677420557563313886988289, f_q))
mstore(add(transcript, 0x2a80), mulmod(mload(add(transcript, 0x2a60)), 21180393220728113421338195116216869725258066600961496947533653125588029756005, f_q))
mstore(add(transcript, 0x2aa0), addmod(mload(add(transcript, 0x1160)), 707849651111161800908210629040405363290297799454537396164551060987778739612, f_q))
mstore(add(transcript, 0x2ac0), mulmod(mload(add(transcript, 0x2a60)), 18801136258871406524726641978934912926273987048785013233465874845411408769764, f_q))
mstore(add(transcript, 0x2ae0), addmod(mload(add(transcript, 0x1160)), 3087106612967868697519763766322362162274377351631021110232329341164399725853, f_q))
mstore(add(transcript, 0x2b00), mulmod(mload(add(transcript, 0x2a60)), 13137266746974929847674828718073699700748973485900204084410541910719500618841, f_q))
mstore(add(transcript, 0x2b20), addmod(mload(add(transcript, 0x1160)), 8750976124864345374571577027183575387799390914515830259287662275856307876776, f_q))
mstore(add(transcript, 0x2b40), mulmod(mload(add(transcript, 0x2a60)), 14204982954615820785730815556166377574172276341958019443243371773666809943588, f_q))
mstore(add(transcript, 0x2b60), addmod(mload(add(transcript, 0x1160)), 7683259917223454436515590189090897514376088058458014900454832412908998552029, f_q))
mstore(add(transcript, 0x2b80), mulmod(mload(add(transcript, 0x2a60)), 9798514389911400568976296423560720718971335345616984532185711118739339214189, f_q))
mstore(add(transcript, 0x2ba0), addmod(mload(add(transcript, 0x1160)), 12089728481927874653270109321696554369577029054799049811512493067836469281428, f_q))
mstore(add(transcript, 0x2bc0), mulmod(mload(add(transcript, 0x2a60)), 5857228514216831962358810454360739186987616060007133076514874820078026801648, f_q))
mstore(add(transcript, 0x2be0), addmod(mload(add(transcript, 0x1160)), 16031014357622443259887595290896535901560748340408901267183329366497781693969, f_q))
mstore(add(transcript, 0x2c00), mulmod(mload(add(transcript, 0x2a60)), 11402394834529375719535454173347509224290498423785625657829583372803806900475, f_q))
mstore(add(transcript, 0x2c20), addmod(mload(add(transcript, 0x1160)), 10485848037309899502710951571909765864257865976630408685868620813772001595142, f_q))
mstore(add(transcript, 0x2c40), mulmod(mload(add(transcript, 0x2a60)), 1, f_q))
mstore(add(transcript, 0x2c60), addmod(mload(add(transcript, 0x1160)), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q))
mstore(add(transcript, 0x2c80), mulmod(mload(add(transcript, 0x2a60)), 21846745818185811051373434299876022191132089169516983080959277716660228899818, f_q))
mstore(add(transcript, 0x2ca0), addmod(mload(add(transcript, 0x1160)), 41497053653464170872971445381252897416275230899051262738926469915579595799, f_q))
mstore(add(transcript, 0x2cc0), mulmod(mload(add(transcript, 0x2a60)), 4443263508319656594054352481848447997537391617204595126809744742387004492585, f_q))
mstore(add(transcript, 0x2ce0), addmod(mload(add(transcript, 0x1160)), 17444979363519618628192053263408827091010972783211439216888459444188804003032, f_q))
{            let prod := mload(add(transcript, 0x2aa0))                prod := mulmod(mload(add(transcript, 0x2ae0)), prod, f_q)                mstore(add(transcript, 0x2d00), prod)                            prod := mulmod(mload(add(transcript, 0x2b20)), prod, f_q)                mstore(add(transcript, 0x2d20), prod)                            prod := mulmod(mload(add(transcript, 0x2b60)), prod, f_q)                mstore(add(transcript, 0x2d40), prod)                            prod := mulmod(mload(add(transcript, 0x2ba0)), prod, f_q)                mstore(add(transcript, 0x2d60), prod)                            prod := mulmod(mload(add(transcript, 0x2be0)), prod, f_q)                mstore(add(transcript, 0x2d80), prod)                            prod := mulmod(mload(add(transcript, 0x2c20)), prod, f_q)                mstore(add(transcript, 0x2da0), prod)                            prod := mulmod(mload(add(transcript, 0x2c60)), prod, f_q)                mstore(add(transcript, 0x2dc0), prod)                            prod := mulmod(mload(add(transcript, 0x2ca0)), prod, f_q)                mstore(add(transcript, 0x2de0), prod)                            prod := mulmod(mload(add(transcript, 0x2ce0)), prod, f_q)                mstore(add(transcript, 0x2e00), prod)                            prod := mulmod(mload(add(transcript, 0x2a40)), prod, f_q)                mstore(add(transcript, 0x2e20), prod)                    }
mstore(add(transcript, 0x2e60), 32)
mstore(add(transcript, 0x2e80), 32)
mstore(add(transcript, 0x2ea0), 32)
mstore(add(transcript, 0x2ec0), mload(add(transcript, 0x2e20)))
mstore(add(transcript, 0x2ee0), 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(add(transcript, 0x2f00), 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, add(transcript, 0x2e60), 0xc0, add(transcript, 0x2e40), 0x20), 1), success)
{                        let inv := mload(add(transcript, 0x2e40))            let v                            v := mload(add(transcript, 0x2a40))                    mstore(add(transcript, 0x2a40), mulmod(mload(add(transcript, 0x2e00)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x2ce0))                    mstore(add(transcript, 0x2ce0), mulmod(mload(add(transcript, 0x2de0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x2ca0))                    mstore(add(transcript, 0x2ca0), mulmod(mload(add(transcript, 0x2dc0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x2c60))                    mstore(add(transcript, 0x2c60), mulmod(mload(add(transcript, 0x2da0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x2c20))                    mstore(add(transcript, 0x2c20), mulmod(mload(add(transcript, 0x2d80)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x2be0))                    mstore(add(transcript, 0x2be0), mulmod(mload(add(transcript, 0x2d60)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x2ba0))                    mstore(add(transcript, 0x2ba0), mulmod(mload(add(transcript, 0x2d40)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x2b60))                    mstore(add(transcript, 0x2b60), mulmod(mload(add(transcript, 0x2d20)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x2b20))                    mstore(add(transcript, 0x2b20), mulmod(mload(add(transcript, 0x2d00)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x2ae0))                    mstore(add(transcript, 0x2ae0), mulmod(mload(add(transcript, 0x2aa0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                mstore(add(transcript, 0x2aa0), inv)        }
mstore(add(transcript, 0x2f20), mulmod(mload(add(transcript, 0x2a80)), mload(add(transcript, 0x2aa0)), f_q))
mstore(add(transcript, 0x2f40), mulmod(mload(add(transcript, 0x2ac0)), mload(add(transcript, 0x2ae0)), f_q))
mstore(add(transcript, 0x2f60), mulmod(mload(add(transcript, 0x2b00)), mload(add(transcript, 0x2b20)), f_q))
mstore(add(transcript, 0x2f80), mulmod(mload(add(transcript, 0x2b40)), mload(add(transcript, 0x2b60)), f_q))
mstore(add(transcript, 0x2fa0), mulmod(mload(add(transcript, 0x2b80)), mload(add(transcript, 0x2ba0)), f_q))
mstore(add(transcript, 0x2fc0), mulmod(mload(add(transcript, 0x2bc0)), mload(add(transcript, 0x2be0)), f_q))
mstore(add(transcript, 0x2fe0), mulmod(mload(add(transcript, 0x2c00)), mload(add(transcript, 0x2c20)), f_q))
mstore(add(transcript, 0x3000), mulmod(mload(add(transcript, 0x2c40)), mload(add(transcript, 0x2c60)), f_q))
mstore(add(transcript, 0x3020), mulmod(mload(add(transcript, 0x2c80)), mload(add(transcript, 0x2ca0)), f_q))
mstore(add(transcript, 0x3040), mulmod(mload(add(transcript, 0x2cc0)), mload(add(transcript, 0x2ce0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3000)), mload(add(transcript, 0x20)), f_q)result := addmod(mulmod(mload(add(transcript, 0x3020)), mload(add(transcript, 0x40)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x3040)), mload(add(transcript, 0x60)), f_q), result, f_q)mstore(add(transcript, 0x3060), result)        }
mstore(add(transcript, 0x3080), addmod(2, sub(f_q, mload(add(transcript, 0x1b40))), f_q))
mstore(add(transcript, 0x30a0), mulmod(mload(add(transcript, 0x3080)), mload(add(transcript, 0x1b40)), f_q))
mstore(add(transcript, 0x30c0), addmod(3, sub(f_q, mload(add(transcript, 0x1b40))), f_q))
mstore(add(transcript, 0x30e0), mulmod(mload(add(transcript, 0x30c0)), mload(add(transcript, 0x30a0)), f_q))
mstore(add(transcript, 0x3100), addmod(4, sub(f_q, mload(add(transcript, 0x1b40))), f_q))
mstore(add(transcript, 0x3120), mulmod(mload(add(transcript, 0x3100)), mload(add(transcript, 0x30e0)), f_q))
mstore(add(transcript, 0x3140), mulmod(mload(add(transcript, 0x11e0)), mload(add(transcript, 0x11c0)), f_q))
mstore(add(transcript, 0x3160), addmod(mload(add(transcript, 0x11a0)), mload(add(transcript, 0x3140)), f_q))
mstore(add(transcript, 0x3180), addmod(mload(add(transcript, 0x3160)), sub(f_q, mload(add(transcript, 0x1200))), f_q))
mstore(add(transcript, 0x31a0), mulmod(mload(add(transcript, 0x3180)), mload(add(transcript, 0x3120)), f_q))
mstore(add(transcript, 0x31c0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x31a0)), f_q))
mstore(add(transcript, 0x31e0), addmod(2, sub(f_q, mload(add(transcript, 0x1b60))), f_q))
mstore(add(transcript, 0x3200), mulmod(mload(add(transcript, 0x31e0)), mload(add(transcript, 0x1b60)), f_q))
mstore(add(transcript, 0x3220), addmod(3, sub(f_q, mload(add(transcript, 0x1b60))), f_q))
mstore(add(transcript, 0x3240), mulmod(mload(add(transcript, 0x3220)), mload(add(transcript, 0x3200)), f_q))
mstore(add(transcript, 0x3260), mulmod(mload(add(transcript, 0x1260)), mload(add(transcript, 0x1240)), f_q))
mstore(add(transcript, 0x3280), addmod(mload(add(transcript, 0x1220)), mload(add(transcript, 0x3260)), f_q))
mstore(add(transcript, 0x32a0), addmod(mload(add(transcript, 0x3280)), sub(f_q, mload(add(transcript, 0x1280))), f_q))
mstore(add(transcript, 0x32c0), mulmod(mload(add(transcript, 0x32a0)), mload(add(transcript, 0x3240)), f_q))
mstore(add(transcript, 0x32e0), addmod(mload(add(transcript, 0x31c0)), mload(add(transcript, 0x32c0)), f_q))
mstore(add(transcript, 0x3300), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x32e0)), f_q))
mstore(add(transcript, 0x3320), mulmod(mload(add(transcript, 0x12e0)), mload(add(transcript, 0x12c0)), f_q))
mstore(add(transcript, 0x3340), addmod(mload(add(transcript, 0x12a0)), mload(add(transcript, 0x3320)), f_q))
mstore(add(transcript, 0x3360), addmod(mload(add(transcript, 0x3340)), sub(f_q, mload(add(transcript, 0x1300))), f_q))
mstore(add(transcript, 0x3380), mulmod(mload(add(transcript, 0x3360)), mload(add(transcript, 0x1b80)), f_q))
mstore(add(transcript, 0x33a0), addmod(mload(add(transcript, 0x3300)), mload(add(transcript, 0x3380)), f_q))
mstore(add(transcript, 0x33c0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x33a0)), f_q))
mstore(add(transcript, 0x33e0), addmod(1, sub(f_q, mload(add(transcript, 0x1b40))), f_q))
mstore(add(transcript, 0x3400), mulmod(mload(add(transcript, 0x33e0)), mload(add(transcript, 0x1b40)), f_q))
mstore(add(transcript, 0x3420), mulmod(mload(add(transcript, 0x30c0)), mload(add(transcript, 0x3400)), f_q))
mstore(add(transcript, 0x3440), mulmod(mload(add(transcript, 0x3100)), mload(add(transcript, 0x3420)), f_q))
mstore(add(transcript, 0x3460), mulmod(mload(add(transcript, 0x1360)), mload(add(transcript, 0x1340)), f_q))
mstore(add(transcript, 0x3480), addmod(mload(add(transcript, 0x1320)), mload(add(transcript, 0x3460)), f_q))
mstore(add(transcript, 0x34a0), addmod(mload(add(transcript, 0x3480)), sub(f_q, mload(add(transcript, 0x1380))), f_q))
mstore(add(transcript, 0x34c0), mulmod(mload(add(transcript, 0x34a0)), mload(add(transcript, 0x3440)), f_q))
mstore(add(transcript, 0x34e0), addmod(mload(add(transcript, 0x33c0)), mload(add(transcript, 0x34c0)), f_q))
mstore(add(transcript, 0x3500), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x34e0)), f_q))
mstore(add(transcript, 0x3520), mulmod(mload(add(transcript, 0x3080)), mload(add(transcript, 0x3400)), f_q))
mstore(add(transcript, 0x3540), mulmod(mload(add(transcript, 0x3100)), mload(add(transcript, 0x3520)), f_q))
mstore(add(transcript, 0x3560), mulmod(mload(add(transcript, 0x13e0)), mload(add(transcript, 0x13c0)), f_q))
mstore(add(transcript, 0x3580), addmod(mload(add(transcript, 0x13a0)), mload(add(transcript, 0x3560)), f_q))
mstore(add(transcript, 0x35a0), addmod(mload(add(transcript, 0x3580)), sub(f_q, mload(add(transcript, 0x1400))), f_q))
mstore(add(transcript, 0x35c0), mulmod(mload(add(transcript, 0x35a0)), mload(add(transcript, 0x3540)), f_q))
mstore(add(transcript, 0x35e0), addmod(mload(add(transcript, 0x3500)), mload(add(transcript, 0x35c0)), f_q))
mstore(add(transcript, 0x3600), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x35e0)), f_q))
mstore(add(transcript, 0x3620), mulmod(mload(add(transcript, 0x30c0)), mload(add(transcript, 0x3520)), f_q))
mstore(add(transcript, 0x3640), mulmod(mload(add(transcript, 0x1460)), mload(add(transcript, 0x1440)), f_q))
mstore(add(transcript, 0x3660), addmod(mload(add(transcript, 0x1420)), mload(add(transcript, 0x3640)), f_q))
mstore(add(transcript, 0x3680), addmod(mload(add(transcript, 0x3660)), sub(f_q, mload(add(transcript, 0x1480))), f_q))
mstore(add(transcript, 0x36a0), mulmod(mload(add(transcript, 0x3680)), mload(add(transcript, 0x3620)), f_q))
mstore(add(transcript, 0x36c0), addmod(mload(add(transcript, 0x3600)), mload(add(transcript, 0x36a0)), f_q))
mstore(add(transcript, 0x36e0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x36c0)), f_q))
mstore(add(transcript, 0x3700), addmod(1, sub(f_q, mload(add(transcript, 0x1b60))), f_q))
mstore(add(transcript, 0x3720), mulmod(mload(add(transcript, 0x3700)), mload(add(transcript, 0x1b60)), f_q))
mstore(add(transcript, 0x3740), mulmod(mload(add(transcript, 0x3220)), mload(add(transcript, 0x3720)), f_q))
mstore(add(transcript, 0x3760), mulmod(mload(add(transcript, 0x14e0)), mload(add(transcript, 0x14c0)), f_q))
mstore(add(transcript, 0x3780), addmod(mload(add(transcript, 0x14a0)), mload(add(transcript, 0x3760)), f_q))
mstore(add(transcript, 0x37a0), addmod(mload(add(transcript, 0x3780)), sub(f_q, mload(add(transcript, 0x1500))), f_q))
mstore(add(transcript, 0x37c0), mulmod(mload(add(transcript, 0x37a0)), mload(add(transcript, 0x3740)), f_q))
mstore(add(transcript, 0x37e0), addmod(mload(add(transcript, 0x36e0)), mload(add(transcript, 0x37c0)), f_q))
mstore(add(transcript, 0x3800), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x37e0)), f_q))
mstore(add(transcript, 0x3820), mulmod(mload(add(transcript, 0x31e0)), mload(add(transcript, 0x3720)), f_q))
mstore(add(transcript, 0x3840), mulmod(mload(add(transcript, 0x1560)), mload(add(transcript, 0x1540)), f_q))
mstore(add(transcript, 0x3860), addmod(mload(add(transcript, 0x1520)), mload(add(transcript, 0x3840)), f_q))
mstore(add(transcript, 0x3880), addmod(mload(add(transcript, 0x3860)), sub(f_q, mload(add(transcript, 0x1580))), f_q))
mstore(add(transcript, 0x38a0), mulmod(mload(add(transcript, 0x3880)), mload(add(transcript, 0x3820)), f_q))
mstore(add(transcript, 0x38c0), addmod(mload(add(transcript, 0x3800)), mload(add(transcript, 0x38a0)), f_q))
mstore(add(transcript, 0x38e0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x38c0)), f_q))
mstore(add(transcript, 0x3900), mulmod(mload(add(transcript, 0x1740)), mload(add(transcript, 0x1b00)), f_q))
mstore(add(transcript, 0x3920), addmod(1, sub(f_q, mload(add(transcript, 0x1740))), f_q))
mstore(add(transcript, 0x3940), mulmod(mload(add(transcript, 0x3920)), mload(add(transcript, 0x3900)), f_q))
mstore(add(transcript, 0x3960), addmod(mload(add(transcript, 0x38e0)), mload(add(transcript, 0x3940)), f_q))
mstore(add(transcript, 0x3980), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3960)), f_q))
mstore(add(transcript, 0x39a0), addmod(mload(add(transcript, 0x15a0)), 21888242871839275222246405745257275088548364400416034343698204186575808495617, f_q))
mstore(add(transcript, 0x39c0), mulmod(mload(add(transcript, 0x39a0)), mload(add(transcript, 0x3900)), f_q))
mstore(add(transcript, 0x39e0), addmod(mload(add(transcript, 0x3980)), mload(add(transcript, 0x39c0)), f_q))
mstore(add(transcript, 0x3a00), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x39e0)), f_q))
mstore(add(transcript, 0x3a20), addmod(mload(add(transcript, 0x15c0)), 21888242871839275222246405745257275088548364400416034343698204186575808495617, f_q))
mstore(add(transcript, 0x3a40), mulmod(mload(add(transcript, 0x3a20)), mload(add(transcript, 0x3900)), f_q))
mstore(add(transcript, 0x3a60), addmod(mload(add(transcript, 0x3a00)), mload(add(transcript, 0x3a40)), f_q))
mstore(add(transcript, 0x3a80), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3a60)), f_q))
mstore(add(transcript, 0x3aa0), addmod(mload(add(transcript, 0x15e0)), 21888242871839275222246405745257275088548364400416034343698204186575808495617, f_q))
mstore(add(transcript, 0x3ac0), mulmod(mload(add(transcript, 0x3aa0)), mload(add(transcript, 0x3900)), f_q))
mstore(add(transcript, 0x3ae0), addmod(mload(add(transcript, 0x3a80)), mload(add(transcript, 0x3ac0)), f_q))
mstore(add(transcript, 0x3b00), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3ae0)), f_q))
mstore(add(transcript, 0x3b20), addmod(mload(add(transcript, 0x1760)), sub(f_q, mload(add(transcript, 0x1740))), f_q))
mstore(add(transcript, 0x3b40), mulmod(mload(add(transcript, 0x3b20)), mload(add(transcript, 0x1b20)), f_q))
mstore(add(transcript, 0x3b60), addmod(1, sub(f_q, mload(add(transcript, 0x3b20))), f_q))
mstore(add(transcript, 0x3b80), mulmod(mload(add(transcript, 0x3b60)), mload(add(transcript, 0x3b40)), f_q))
mstore(add(transcript, 0x3ba0), addmod(mload(add(transcript, 0x3b00)), mload(add(transcript, 0x3b80)), f_q))
mstore(add(transcript, 0x3bc0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3ba0)), f_q))
mstore(add(transcript, 0x3be0), mulmod(mload(add(transcript, 0x1740)), mload(add(transcript, 0x1b20)), f_q))
mstore(add(transcript, 0x3c00), mulmod(mload(add(transcript, 0x3920)), mload(add(transcript, 0x3be0)), f_q))
mstore(add(transcript, 0x3c20), addmod(mload(add(transcript, 0x3bc0)), mload(add(transcript, 0x3c00)), f_q))
mstore(add(transcript, 0x3c40), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3c20)), f_q))
mstore(add(transcript, 0x3c60), addmod(1, sub(f_q, mload(add(transcript, 0x1ec0))), f_q))
mstore(add(transcript, 0x3c80), mulmod(mload(add(transcript, 0x3c60)), mload(add(transcript, 0x3000)), f_q))
mstore(add(transcript, 0x3ca0), addmod(mload(add(transcript, 0x3c40)), mload(add(transcript, 0x3c80)), f_q))
mstore(add(transcript, 0x3cc0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3ca0)), f_q))
mstore(add(transcript, 0x3ce0), mulmod(mload(add(transcript, 0x20a0)), mload(add(transcript, 0x20a0)), f_q))
mstore(add(transcript, 0x3d00), addmod(mload(add(transcript, 0x3ce0)), sub(f_q, mload(add(transcript, 0x20a0))), f_q))
mstore(add(transcript, 0x3d20), mulmod(mload(add(transcript, 0x3d00)), mload(add(transcript, 0x2f20)), f_q))
mstore(add(transcript, 0x3d40), addmod(mload(add(transcript, 0x3cc0)), mload(add(transcript, 0x3d20)), f_q))
mstore(add(transcript, 0x3d60), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3d40)), f_q))
mstore(add(transcript, 0x3d80), addmod(mload(add(transcript, 0x1f20)), sub(f_q, mload(add(transcript, 0x1f00))), f_q))
mstore(add(transcript, 0x3da0), mulmod(mload(add(transcript, 0x3d80)), mload(add(transcript, 0x3000)), f_q))
mstore(add(transcript, 0x3dc0), addmod(mload(add(transcript, 0x3d60)), mload(add(transcript, 0x3da0)), f_q))
mstore(add(transcript, 0x3de0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3dc0)), f_q))
mstore(add(transcript, 0x3e00), addmod(mload(add(transcript, 0x1f80)), sub(f_q, mload(add(transcript, 0x1f60))), f_q))
mstore(add(transcript, 0x3e20), mulmod(mload(add(transcript, 0x3e00)), mload(add(transcript, 0x3000)), f_q))
mstore(add(transcript, 0x3e40), addmod(mload(add(transcript, 0x3de0)), mload(add(transcript, 0x3e20)), f_q))
mstore(add(transcript, 0x3e60), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3e40)), f_q))
mstore(add(transcript, 0x3e80), addmod(mload(add(transcript, 0x1fe0)), sub(f_q, mload(add(transcript, 0x1fc0))), f_q))
mstore(add(transcript, 0x3ea0), mulmod(mload(add(transcript, 0x3e80)), mload(add(transcript, 0x3000)), f_q))
mstore(add(transcript, 0x3ec0), addmod(mload(add(transcript, 0x3e60)), mload(add(transcript, 0x3ea0)), f_q))
mstore(add(transcript, 0x3ee0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3ec0)), f_q))
mstore(add(transcript, 0x3f00), addmod(mload(add(transcript, 0x2040)), sub(f_q, mload(add(transcript, 0x2020))), f_q))
mstore(add(transcript, 0x3f20), mulmod(mload(add(transcript, 0x3f00)), mload(add(transcript, 0x3000)), f_q))
mstore(add(transcript, 0x3f40), addmod(mload(add(transcript, 0x3ee0)), mload(add(transcript, 0x3f20)), f_q))
mstore(add(transcript, 0x3f60), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3f40)), f_q))
mstore(add(transcript, 0x3f80), addmod(mload(add(transcript, 0x20a0)), sub(f_q, mload(add(transcript, 0x2080))), f_q))
mstore(add(transcript, 0x3fa0), mulmod(mload(add(transcript, 0x3f80)), mload(add(transcript, 0x3000)), f_q))
mstore(add(transcript, 0x3fc0), addmod(mload(add(transcript, 0x3f60)), mload(add(transcript, 0x3fa0)), f_q))
mstore(add(transcript, 0x3fe0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x3fc0)), f_q))
mstore(add(transcript, 0x4000), addmod(1, sub(f_q, mload(add(transcript, 0x2f20))), f_q))
mstore(add(transcript, 0x4020), addmod(mload(add(transcript, 0x2f40)), mload(add(transcript, 0x2f60)), f_q))
mstore(add(transcript, 0x4040), addmod(mload(add(transcript, 0x4020)), mload(add(transcript, 0x2f80)), f_q))
mstore(add(transcript, 0x4060), addmod(mload(add(transcript, 0x4040)), mload(add(transcript, 0x2fa0)), f_q))
mstore(add(transcript, 0x4080), addmod(mload(add(transcript, 0x4060)), mload(add(transcript, 0x2fc0)), f_q))
mstore(add(transcript, 0x40a0), addmod(mload(add(transcript, 0x4080)), mload(add(transcript, 0x2fe0)), f_q))
mstore(add(transcript, 0x40c0), addmod(mload(add(transcript, 0x4000)), sub(f_q, mload(add(transcript, 0x40a0))), f_q))
mstore(add(transcript, 0x40e0), mulmod(mload(add(transcript, 0x1bc0)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4100), addmod(mload(add(transcript, 0x1840)), mload(add(transcript, 0x40e0)), f_q))
mstore(add(transcript, 0x4120), addmod(mload(add(transcript, 0x4100)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4140), mulmod(mload(add(transcript, 0x1be0)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4160), addmod(mload(add(transcript, 0x11a0)), mload(add(transcript, 0x4140)), f_q))
mstore(add(transcript, 0x4180), addmod(mload(add(transcript, 0x4160)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x41a0), mulmod(mload(add(transcript, 0x4180)), mload(add(transcript, 0x4120)), f_q))
mstore(add(transcript, 0x41c0), mulmod(mload(add(transcript, 0x1c00)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x41e0), addmod(mload(add(transcript, 0x1220)), mload(add(transcript, 0x41c0)), f_q))
mstore(add(transcript, 0x4200), addmod(mload(add(transcript, 0x41e0)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4220), mulmod(mload(add(transcript, 0x4200)), mload(add(transcript, 0x41a0)), f_q))
mstore(add(transcript, 0x4240), mulmod(mload(add(transcript, 0x1c20)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4260), addmod(mload(add(transcript, 0x12a0)), mload(add(transcript, 0x4240)), f_q))
mstore(add(transcript, 0x4280), addmod(mload(add(transcript, 0x4260)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x42a0), mulmod(mload(add(transcript, 0x4280)), mload(add(transcript, 0x4220)), f_q))
mstore(add(transcript, 0x42c0), mulmod(mload(add(transcript, 0x42a0)), mload(add(transcript, 0x1ee0)), f_q))
mstore(add(transcript, 0x42e0), mulmod(1, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4300), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x42e0)), f_q))
mstore(add(transcript, 0x4320), addmod(mload(add(transcript, 0x1840)), mload(add(transcript, 0x4300)), f_q))
mstore(add(transcript, 0x4340), addmod(mload(add(transcript, 0x4320)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4360), mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4380), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x4360)), f_q))
mstore(add(transcript, 0x43a0), addmod(mload(add(transcript, 0x11a0)), mload(add(transcript, 0x4380)), f_q))
mstore(add(transcript, 0x43c0), addmod(mload(add(transcript, 0x43a0)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x43e0), mulmod(mload(add(transcript, 0x43c0)), mload(add(transcript, 0x4340)), f_q))
mstore(add(transcript, 0x4400), mulmod(8910878055287538404433155982483128285667088683464058436815641868457422632747, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4420), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x4400)), f_q))
mstore(add(transcript, 0x4440), addmod(mload(add(transcript, 0x1220)), mload(add(transcript, 0x4420)), f_q))
mstore(add(transcript, 0x4460), addmod(mload(add(transcript, 0x4440)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4480), mulmod(mload(add(transcript, 0x4460)), mload(add(transcript, 0x43e0)), f_q))
mstore(add(transcript, 0x44a0), mulmod(11166246659983828508719468090013646171463329086121580628794302409516816350802, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x44c0), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x44a0)), f_q))
mstore(add(transcript, 0x44e0), addmod(mload(add(transcript, 0x12a0)), mload(add(transcript, 0x44c0)), f_q))
mstore(add(transcript, 0x4500), addmod(mload(add(transcript, 0x44e0)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4520), mulmod(mload(add(transcript, 0x4500)), mload(add(transcript, 0x4480)), f_q))
mstore(add(transcript, 0x4540), mulmod(mload(add(transcript, 0x4520)), mload(add(transcript, 0x1ec0)), f_q))
mstore(add(transcript, 0x4560), addmod(mload(add(transcript, 0x42c0)), sub(f_q, mload(add(transcript, 0x4540))), f_q))
mstore(add(transcript, 0x4580), mulmod(mload(add(transcript, 0x4560)), mload(add(transcript, 0x40c0)), f_q))
mstore(add(transcript, 0x45a0), addmod(mload(add(transcript, 0x3fe0)), mload(add(transcript, 0x4580)), f_q))
mstore(add(transcript, 0x45c0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x45a0)), f_q))
mstore(add(transcript, 0x45e0), mulmod(mload(add(transcript, 0x1c40)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4600), addmod(mload(add(transcript, 0x1320)), mload(add(transcript, 0x45e0)), f_q))
mstore(add(transcript, 0x4620), addmod(mload(add(transcript, 0x4600)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4640), mulmod(mload(add(transcript, 0x1c60)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4660), addmod(mload(add(transcript, 0x13a0)), mload(add(transcript, 0x4640)), f_q))
mstore(add(transcript, 0x4680), addmod(mload(add(transcript, 0x4660)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x46a0), mulmod(mload(add(transcript, 0x4680)), mload(add(transcript, 0x4620)), f_q))
mstore(add(transcript, 0x46c0), mulmod(mload(add(transcript, 0x1c80)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x46e0), addmod(mload(add(transcript, 0x1420)), mload(add(transcript, 0x46c0)), f_q))
mstore(add(transcript, 0x4700), addmod(mload(add(transcript, 0x46e0)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4720), mulmod(mload(add(transcript, 0x4700)), mload(add(transcript, 0x46a0)), f_q))
mstore(add(transcript, 0x4740), mulmod(mload(add(transcript, 0x1ca0)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4760), addmod(mload(add(transcript, 0x14a0)), mload(add(transcript, 0x4740)), f_q))
mstore(add(transcript, 0x4780), addmod(mload(add(transcript, 0x4760)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x47a0), mulmod(mload(add(transcript, 0x4780)), mload(add(transcript, 0x4720)), f_q))
mstore(add(transcript, 0x47c0), mulmod(mload(add(transcript, 0x47a0)), mload(add(transcript, 0x1f40)), f_q))
mstore(add(transcript, 0x47e0), mulmod(284840088355319032285349970403338060113257071685626700086398481893096618818, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4800), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x47e0)), f_q))
mstore(add(transcript, 0x4820), addmod(mload(add(transcript, 0x1320)), mload(add(transcript, 0x4800)), f_q))
mstore(add(transcript, 0x4840), addmod(mload(add(transcript, 0x4820)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4860), mulmod(21134065618345176623193549882539580312263652408302468683943992798037078993309, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4880), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x4860)), f_q))
mstore(add(transcript, 0x48a0), addmod(mload(add(transcript, 0x13a0)), mload(add(transcript, 0x4880)), f_q))
mstore(add(transcript, 0x48c0), addmod(mload(add(transcript, 0x48a0)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x48e0), mulmod(mload(add(transcript, 0x48c0)), mload(add(transcript, 0x4840)), f_q))
mstore(add(transcript, 0x4900), mulmod(5625741653535312224677218588085279924365897425605943700675464992185016992283, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4920), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x4900)), f_q))
mstore(add(transcript, 0x4940), addmod(mload(add(transcript, 0x1420)), mload(add(transcript, 0x4920)), f_q))
mstore(add(transcript, 0x4960), addmod(mload(add(transcript, 0x4940)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4980), mulmod(mload(add(transcript, 0x4960)), mload(add(transcript, 0x48e0)), f_q))
mstore(add(transcript, 0x49a0), mulmod(14704729814417906439424896605881467874595262020190401576785074330126828718155, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x49c0), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x49a0)), f_q))
mstore(add(transcript, 0x49e0), addmod(mload(add(transcript, 0x14a0)), mload(add(transcript, 0x49c0)), f_q))
mstore(add(transcript, 0x4a00), addmod(mload(add(transcript, 0x49e0)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4a20), mulmod(mload(add(transcript, 0x4a00)), mload(add(transcript, 0x4980)), f_q))
mstore(add(transcript, 0x4a40), mulmod(mload(add(transcript, 0x4a20)), mload(add(transcript, 0x1f20)), f_q))
mstore(add(transcript, 0x4a60), addmod(mload(add(transcript, 0x47c0)), sub(f_q, mload(add(transcript, 0x4a40))), f_q))
mstore(add(transcript, 0x4a80), mulmod(mload(add(transcript, 0x4a60)), mload(add(transcript, 0x40c0)), f_q))
mstore(add(transcript, 0x4aa0), addmod(mload(add(transcript, 0x45c0)), mload(add(transcript, 0x4a80)), f_q))
mstore(add(transcript, 0x4ac0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x4aa0)), f_q))
mstore(add(transcript, 0x4ae0), mulmod(mload(add(transcript, 0x1cc0)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4b00), addmod(mload(add(transcript, 0x1520)), mload(add(transcript, 0x4ae0)), f_q))
mstore(add(transcript, 0x4b20), addmod(mload(add(transcript, 0x4b00)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4b40), mulmod(mload(add(transcript, 0x1ce0)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4b60), addmod(mload(add(transcript, 0x15a0)), mload(add(transcript, 0x4b40)), f_q))
mstore(add(transcript, 0x4b80), addmod(mload(add(transcript, 0x4b60)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4ba0), mulmod(mload(add(transcript, 0x4b80)), mload(add(transcript, 0x4b20)), f_q))
mstore(add(transcript, 0x4bc0), mulmod(mload(add(transcript, 0x1d00)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4be0), addmod(mload(add(transcript, 0x15c0)), mload(add(transcript, 0x4bc0)), f_q))
mstore(add(transcript, 0x4c00), addmod(mload(add(transcript, 0x4be0)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4c20), mulmod(mload(add(transcript, 0x4c00)), mload(add(transcript, 0x4ba0)), f_q))
mstore(add(transcript, 0x4c40), mulmod(mload(add(transcript, 0x1d20)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4c60), addmod(mload(add(transcript, 0x15e0)), mload(add(transcript, 0x4c40)), f_q))
mstore(add(transcript, 0x4c80), addmod(mload(add(transcript, 0x4c60)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4ca0), mulmod(mload(add(transcript, 0x4c80)), mload(add(transcript, 0x4c20)), f_q))
mstore(add(transcript, 0x4cc0), mulmod(mload(add(transcript, 0x4ca0)), mload(add(transcript, 0x1fa0)), f_q))
mstore(add(transcript, 0x4ce0), mulmod(8343274462013750416000956870576256937330525306073862550863787263304548803879, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4d00), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x4ce0)), f_q))
mstore(add(transcript, 0x4d20), addmod(mload(add(transcript, 0x1520)), mload(add(transcript, 0x4d00)), f_q))
mstore(add(transcript, 0x4d40), addmod(mload(add(transcript, 0x4d20)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4d60), mulmod(20928372310071051017340352686640453451620397549739756658327314209761852842004, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4d80), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x4d60)), f_q))
mstore(add(transcript, 0x4da0), addmod(mload(add(transcript, 0x15a0)), mload(add(transcript, 0x4d80)), f_q))
mstore(add(transcript, 0x4dc0), addmod(mload(add(transcript, 0x4da0)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4de0), mulmod(mload(add(transcript, 0x4dc0)), mload(add(transcript, 0x4d40)), f_q))
mstore(add(transcript, 0x4e00), mulmod(15845651941796975697993789271154426079663327509658641548785793587449119139335, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4e20), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x4e00)), f_q))
mstore(add(transcript, 0x4e40), addmod(mload(add(transcript, 0x15c0)), mload(add(transcript, 0x4e20)), f_q))
mstore(add(transcript, 0x4e60), addmod(mload(add(transcript, 0x4e40)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4e80), mulmod(mload(add(transcript, 0x4e60)), mload(add(transcript, 0x4de0)), f_q))
mstore(add(transcript, 0x4ea0), mulmod(8045145839887181143520022567602912517500076612542816225981084745629998235872, mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x4ec0), mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x4ea0)), f_q))
mstore(add(transcript, 0x4ee0), addmod(mload(add(transcript, 0x15e0)), mload(add(transcript, 0x4ec0)), f_q))
mstore(add(transcript, 0x4f00), addmod(mload(add(transcript, 0x4ee0)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x4f20), mulmod(mload(add(transcript, 0x4f00)), mload(add(transcript, 0x4e80)), f_q))
mstore(add(transcript, 0x4f40), mulmod(mload(add(transcript, 0x4f20)), mload(add(transcript, 0x1f80)), f_q))
mstore(add(transcript, 0x4f60), addmod(mload(add(transcript, 0x4cc0)), sub(f_q, mload(add(transcript, 0x4f40))), f_q))
mstore(add(transcript, 0x4f80), mulmod(mload(add(transcript, 0x4f60)), mload(add(transcript, 0x40c0)), f_q))
mstore(add(transcript, 0x4fa0), addmod(mload(add(transcript, 0x4ac0)), mload(add(transcript, 0x4f80)), f_q))
mstore(add(transcript, 0x4fc0), mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x4fa0)), f_q))
mstore(add(transcript, 0x4fe0), mulmod(mload(add(transcript, 0x1d40)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x5000), addmod(mload(add(transcript, 0x1600)), mload(add(transcript, 0x4fe0)), f_q))
mstore(add(transcript, 0x5020), addmod(mload(add(transcript, 0x5000)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x5040), mulmod(mload(add(transcript, 0x1d60)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x5060), addmod(mload(add(transcript, 0x1620)), mload(add(transcript, 0x5040)), f_q))
mstore(add(transcript, 0x5080), addmod(mload(add(transcript, 0x5060)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x50a0), mulmod(mload(add(transcript, 0x5080)), mload(add(transcript, 0x5020)), f_q))
mstore(add(transcript, 0x50c0), mulmod(mload(add(transcript, 0x1d80)), mload(add(transcript, 0xb00)), f_q))
mstore(add(transcript, 0x50e0), addmod(mload(add(transcript, 0x1640)), mload(add(transcript, 0x50c0)), f_q))
mstore(add(transcript, 0x5100), addmod(mload(add(transcript, 0x50e0)), mload(add(transcript, 0xb60)), f_q))
mstore(add(transcript, 0x5120), mulmod(mload(add(transcript, 0x5100)), mload(add(transcript, 0x50a0)), f_q))

        }}
        // transcriptBytes = abi.encode(transcript.length, transcript);
        bytes32[] memory newTranscript = new bytes32[](_transcript.length);
        for(uint i=0; i<_transcript.length; i++) {
            newTranscript[i] = transcript[i];
        }
        return (success, newTranscript);
    } 
}
