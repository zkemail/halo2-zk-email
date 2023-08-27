// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierFuncAbst.sol";

contract VerifierFunc0 is VerifierFuncAbst {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes32[6992] memory transcript
    ) public view override returns (bool, bytes32[6992] memory) {
        // bytes32[6992] memory transcript;
        // require(_transcript.length == 6992, "transcript length is not 6992");
        // if(_transcript.length != 0) {
        //     transcript = abi.decode(_transcript, (bytes32[6992]));
        // }
        // for(uint i=0; i<_transcript.length; i++) {
        //     transcript[i] = _transcript[i];
        // }
        
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
mstore(add(transcript, 0x0), 9399697837613383306212633407895587494293400898085558083444893857172897741534)

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

        {            let x := mload(add(proof, 0x5a0))            mstore(add(transcript, 0x600), x)            let y := mload(add(proof, 0x5c0))            mstore(add(transcript, 0x620), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x5e0))            mstore(add(transcript, 0x640), x)            let y := mload(add(proof, 0x600))            mstore(add(transcript, 0x660), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x620))            mstore(add(transcript, 0x680), x)            let y := mload(add(proof, 0x640))            mstore(add(transcript, 0x6a0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x660))            mstore(add(transcript, 0x6c0), x)            let y := mload(add(proof, 0x680))            mstore(add(transcript, 0x6e0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x6a0))            mstore(add(transcript, 0x700), x)            let y := mload(add(proof, 0x6c0))            mstore(add(transcript, 0x720), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x6e0))            mstore(add(transcript, 0x740), x)            let y := mload(add(proof, 0x700))            mstore(add(transcript, 0x760), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x720))            mstore(add(transcript, 0x780), x)            let y := mload(add(proof, 0x740))            mstore(add(transcript, 0x7a0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x760))            mstore(add(transcript, 0x7c0), x)            let y := mload(add(proof, 0x780))            mstore(add(transcript, 0x7e0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x7a0))            mstore(add(transcript, 0x800), x)            let y := mload(add(proof, 0x7c0))            mstore(add(transcript, 0x820), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x7e0))            mstore(add(transcript, 0x840), x)            let y := mload(add(proof, 0x800))            mstore(add(transcript, 0x860), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x820))            mstore(add(transcript, 0x880), x)            let y := mload(add(proof, 0x840))            mstore(add(transcript, 0x8a0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x860))            mstore(add(transcript, 0x8c0), x)            let y := mload(add(proof, 0x880))            mstore(add(transcript, 0x8e0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x8a0))            mstore(add(transcript, 0x900), x)            let y := mload(add(proof, 0x8c0))            mstore(add(transcript, 0x920), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x8e0))            mstore(add(transcript, 0x940), x)            let y := mload(add(proof, 0x900))            mstore(add(transcript, 0x960), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x920))            mstore(add(transcript, 0x980), x)            let y := mload(add(proof, 0x940))            mstore(add(transcript, 0x9a0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x960))            mstore(add(transcript, 0x9c0), x)            let y := mload(add(proof, 0x980))            mstore(add(transcript, 0x9e0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x9a0))            mstore(add(transcript, 0xa00), x)            let y := mload(add(proof, 0x9c0))            mstore(add(transcript, 0xa20), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x9e0))            mstore(add(transcript, 0xa40), x)            let y := mload(add(proof, 0xa00))            mstore(add(transcript, 0xa60), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xa20))            mstore(add(transcript, 0xa80), x)            let y := mload(add(proof, 0xa40))            mstore(add(transcript, 0xaa0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xa60))            mstore(add(transcript, 0xac0), x)            let y := mload(add(proof, 0xa80))            mstore(add(transcript, 0xae0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xaa0))            mstore(add(transcript, 0xb00), x)            let y := mload(add(proof, 0xac0))            mstore(add(transcript, 0xb20), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xae0))            mstore(add(transcript, 0xb40), x)            let y := mload(add(proof, 0xb00))            mstore(add(transcript, 0xb60), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xb20))            mstore(add(transcript, 0xb80), x)            let y := mload(add(proof, 0xb40))            mstore(add(transcript, 0xba0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xb60))            mstore(add(transcript, 0xbc0), x)            let y := mload(add(proof, 0xb80))            mstore(add(transcript, 0xbe0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xba0))            mstore(add(transcript, 0xc00), x)            let y := mload(add(proof, 0xbc0))            mstore(add(transcript, 0xc20), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xbe0))            mstore(add(transcript, 0xc40), x)            let y := mload(add(proof, 0xc00))            mstore(add(transcript, 0xc60), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xc20))            mstore(add(transcript, 0xc80), x)            let y := mload(add(proof, 0xc40))            mstore(add(transcript, 0xca0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xc60))            mstore(add(transcript, 0xcc0), x)            let y := mload(add(proof, 0xc80))            mstore(add(transcript, 0xce0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xca0))            mstore(add(transcript, 0xd00), x)            let y := mload(add(proof, 0xcc0))            mstore(add(transcript, 0xd20), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xce0))            mstore(add(transcript, 0xd40), x)            let y := mload(add(proof, 0xd00))            mstore(add(transcript, 0xd60), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xd20))            mstore(add(transcript, 0xd80), x)            let y := mload(add(proof, 0xd40))            mstore(add(transcript, 0xda0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xd60))            mstore(add(transcript, 0xdc0), x)            let y := mload(add(proof, 0xd80))            mstore(add(transcript, 0xde0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xda0))            mstore(add(transcript, 0xe00), x)            let y := mload(add(proof, 0xdc0))            mstore(add(transcript, 0xe20), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xde0))            mstore(add(transcript, 0xe40), x)            let y := mload(add(proof, 0xe00))            mstore(add(transcript, 0xe60), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xe20))            mstore(add(transcript, 0xe80), x)            let y := mload(add(proof, 0xe40))            mstore(add(transcript, 0xea0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xe60))            mstore(add(transcript, 0xec0), x)            let y := mload(add(proof, 0xe80))            mstore(add(transcript, 0xee0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xea0))            mstore(add(transcript, 0xf00), x)            let y := mload(add(proof, 0xec0))            mstore(add(transcript, 0xf20), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0xf40), keccak256(add(transcript, 0x0), 3904))
{            let hash := mload(add(transcript, 0xf40))            mstore(add(transcript, 0xf60), mod(hash, f_q))            mstore(add(transcript, 0xf80), hash)        }

        {            let x := mload(add(proof, 0xee0))            mstore(add(transcript, 0xfa0), x)            let y := mload(add(proof, 0xf00))            mstore(add(transcript, 0xfc0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xf20))            mstore(add(transcript, 0xfe0), x)            let y := mload(add(proof, 0xf40))            mstore(add(transcript, 0x1000), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xf60))            mstore(add(transcript, 0x1020), x)            let y := mload(add(proof, 0xf80))            mstore(add(transcript, 0x1040), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xfa0))            mstore(add(transcript, 0x1060), x)            let y := mload(add(proof, 0xfc0))            mstore(add(transcript, 0x1080), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0xfe0))            mstore(add(transcript, 0x10a0), x)            let y := mload(add(proof, 0x1000))            mstore(add(transcript, 0x10c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1020))            mstore(add(transcript, 0x10e0), x)            let y := mload(add(proof, 0x1040))            mstore(add(transcript, 0x1100), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1060))            mstore(add(transcript, 0x1120), x)            let y := mload(add(proof, 0x1080))            mstore(add(transcript, 0x1140), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x10a0))            mstore(add(transcript, 0x1160), x)            let y := mload(add(proof, 0x10c0))            mstore(add(transcript, 0x1180), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x10e0))            mstore(add(transcript, 0x11a0), x)            let y := mload(add(proof, 0x1100))            mstore(add(transcript, 0x11c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1120))            mstore(add(transcript, 0x11e0), x)            let y := mload(add(proof, 0x1140))            mstore(add(transcript, 0x1200), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1160))            mstore(add(transcript, 0x1220), x)            let y := mload(add(proof, 0x1180))            mstore(add(transcript, 0x1240), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x11a0))            mstore(add(transcript, 0x1260), x)            let y := mload(add(proof, 0x11c0))            mstore(add(transcript, 0x1280), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x11e0))            mstore(add(transcript, 0x12a0), x)            let y := mload(add(proof, 0x1200))            mstore(add(transcript, 0x12c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1220))            mstore(add(transcript, 0x12e0), x)            let y := mload(add(proof, 0x1240))            mstore(add(transcript, 0x1300), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1260))            mstore(add(transcript, 0x1320), x)            let y := mload(add(proof, 0x1280))            mstore(add(transcript, 0x1340), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x12a0))            mstore(add(transcript, 0x1360), x)            let y := mload(add(proof, 0x12c0))            mstore(add(transcript, 0x1380), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x12e0))            mstore(add(transcript, 0x13a0), x)            let y := mload(add(proof, 0x1300))            mstore(add(transcript, 0x13c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1320))            mstore(add(transcript, 0x13e0), x)            let y := mload(add(proof, 0x1340))            mstore(add(transcript, 0x1400), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1360))            mstore(add(transcript, 0x1420), x)            let y := mload(add(proof, 0x1380))            mstore(add(transcript, 0x1440), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x13a0))            mstore(add(transcript, 0x1460), x)            let y := mload(add(proof, 0x13c0))            mstore(add(transcript, 0x1480), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x13e0))            mstore(add(transcript, 0x14a0), x)            let y := mload(add(proof, 0x1400))            mstore(add(transcript, 0x14c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1420))            mstore(add(transcript, 0x14e0), x)            let y := mload(add(proof, 0x1440))            mstore(add(transcript, 0x1500), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1460))            mstore(add(transcript, 0x1520), x)            let y := mload(add(proof, 0x1480))            mstore(add(transcript, 0x1540), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x14a0))            mstore(add(transcript, 0x1560), x)            let y := mload(add(proof, 0x14c0))            mstore(add(transcript, 0x1580), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x14e0))            mstore(add(transcript, 0x15a0), x)            let y := mload(add(proof, 0x1500))            mstore(add(transcript, 0x15c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1520))            mstore(add(transcript, 0x15e0), x)            let y := mload(add(proof, 0x1540))            mstore(add(transcript, 0x1600), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1560))            mstore(add(transcript, 0x1620), x)            let y := mload(add(proof, 0x1580))            mstore(add(transcript, 0x1640), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x15a0))            mstore(add(transcript, 0x1660), x)            let y := mload(add(proof, 0x15c0))            mstore(add(transcript, 0x1680), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x15e0))            mstore(add(transcript, 0x16a0), x)            let y := mload(add(proof, 0x1600))            mstore(add(transcript, 0x16c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1620))            mstore(add(transcript, 0x16e0), x)            let y := mload(add(proof, 0x1640))            mstore(add(transcript, 0x1700), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1660))            mstore(add(transcript, 0x1720), x)            let y := mload(add(proof, 0x1680))            mstore(add(transcript, 0x1740), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x16a0))            mstore(add(transcript, 0x1760), x)            let y := mload(add(proof, 0x16c0))            mstore(add(transcript, 0x1780), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x16e0))            mstore(add(transcript, 0x17a0), x)            let y := mload(add(proof, 0x1700))            mstore(add(transcript, 0x17c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1720))            mstore(add(transcript, 0x17e0), x)            let y := mload(add(proof, 0x1740))            mstore(add(transcript, 0x1800), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1760))            mstore(add(transcript, 0x1820), x)            let y := mload(add(proof, 0x1780))            mstore(add(transcript, 0x1840), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x17a0))            mstore(add(transcript, 0x1860), x)            let y := mload(add(proof, 0x17c0))            mstore(add(transcript, 0x1880), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x17e0))            mstore(add(transcript, 0x18a0), x)            let y := mload(add(proof, 0x1800))            mstore(add(transcript, 0x18c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1820))            mstore(add(transcript, 0x18e0), x)            let y := mload(add(proof, 0x1840))            mstore(add(transcript, 0x1900), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1860))            mstore(add(transcript, 0x1920), x)            let y := mload(add(proof, 0x1880))            mstore(add(transcript, 0x1940), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x18a0))            mstore(add(transcript, 0x1960), x)            let y := mload(add(proof, 0x18c0))            mstore(add(transcript, 0x1980), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x18e0))            mstore(add(transcript, 0x19a0), x)            let y := mload(add(proof, 0x1900))            mstore(add(transcript, 0x19c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1920))            mstore(add(transcript, 0x19e0), x)            let y := mload(add(proof, 0x1940))            mstore(add(transcript, 0x1a00), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1960))            mstore(add(transcript, 0x1a20), x)            let y := mload(add(proof, 0x1980))            mstore(add(transcript, 0x1a40), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x19a0))            mstore(add(transcript, 0x1a60), x)            let y := mload(add(proof, 0x19c0))            mstore(add(transcript, 0x1a80), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x19e0))            mstore(add(transcript, 0x1aa0), x)            let y := mload(add(proof, 0x1a00))            mstore(add(transcript, 0x1ac0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1a20))            mstore(add(transcript, 0x1ae0), x)            let y := mload(add(proof, 0x1a40))            mstore(add(transcript, 0x1b00), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1a60))            mstore(add(transcript, 0x1b20), x)            let y := mload(add(proof, 0x1a80))            mstore(add(transcript, 0x1b40), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1aa0))            mstore(add(transcript, 0x1b60), x)            let y := mload(add(proof, 0x1ac0))            mstore(add(transcript, 0x1b80), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0x1ba0), keccak256(add(transcript, 0xf80), 3104))
{            let hash := mload(add(transcript, 0x1ba0))            mstore(add(transcript, 0x1bc0), mod(hash, f_q))            mstore(add(transcript, 0x1be0), hash)        }
mstore8(add(transcript, 0x1c00), 1)
mstore(add(transcript, 0x1c00), keccak256(add(transcript, 0x1be0), 33))
{            let hash := mload(add(transcript, 0x1c00))            mstore(add(transcript, 0x1c20), mod(hash, f_q))            mstore(add(transcript, 0x1c40), hash)        }

        {            let x := mload(add(proof, 0x1ae0))            mstore(add(transcript, 0x1c60), x)            let y := mload(add(proof, 0x1b00))            mstore(add(transcript, 0x1c80), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1b20))            mstore(add(transcript, 0x1ca0), x)            let y := mload(add(proof, 0x1b40))            mstore(add(transcript, 0x1cc0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1b60))            mstore(add(transcript, 0x1ce0), x)            let y := mload(add(proof, 0x1b80))            mstore(add(transcript, 0x1d00), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1ba0))            mstore(add(transcript, 0x1d20), x)            let y := mload(add(proof, 0x1bc0))            mstore(add(transcript, 0x1d40), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1be0))            mstore(add(transcript, 0x1d60), x)            let y := mload(add(proof, 0x1c00))            mstore(add(transcript, 0x1d80), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1c20))            mstore(add(transcript, 0x1da0), x)            let y := mload(add(proof, 0x1c40))            mstore(add(transcript, 0x1dc0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1c60))            mstore(add(transcript, 0x1de0), x)            let y := mload(add(proof, 0x1c80))            mstore(add(transcript, 0x1e00), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1ca0))            mstore(add(transcript, 0x1e20), x)            let y := mload(add(proof, 0x1cc0))            mstore(add(transcript, 0x1e40), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1ce0))            mstore(add(transcript, 0x1e60), x)            let y := mload(add(proof, 0x1d00))            mstore(add(transcript, 0x1e80), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1d20))            mstore(add(transcript, 0x1ea0), x)            let y := mload(add(proof, 0x1d40))            mstore(add(transcript, 0x1ec0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1d60))            mstore(add(transcript, 0x1ee0), x)            let y := mload(add(proof, 0x1d80))            mstore(add(transcript, 0x1f00), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1da0))            mstore(add(transcript, 0x1f20), x)            let y := mload(add(proof, 0x1dc0))            mstore(add(transcript, 0x1f40), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1de0))            mstore(add(transcript, 0x1f60), x)            let y := mload(add(proof, 0x1e00))            mstore(add(transcript, 0x1f80), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1e20))            mstore(add(transcript, 0x1fa0), x)            let y := mload(add(proof, 0x1e40))            mstore(add(transcript, 0x1fc0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1e60))            mstore(add(transcript, 0x1fe0), x)            let y := mload(add(proof, 0x1e80))            mstore(add(transcript, 0x2000), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1ea0))            mstore(add(transcript, 0x2020), x)            let y := mload(add(proof, 0x1ec0))            mstore(add(transcript, 0x2040), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1ee0))            mstore(add(transcript, 0x2060), x)            let y := mload(add(proof, 0x1f00))            mstore(add(transcript, 0x2080), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1f20))            mstore(add(transcript, 0x20a0), x)            let y := mload(add(proof, 0x1f40))            mstore(add(transcript, 0x20c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1f60))            mstore(add(transcript, 0x20e0), x)            let y := mload(add(proof, 0x1f80))            mstore(add(transcript, 0x2100), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1fa0))            mstore(add(transcript, 0x2120), x)            let y := mload(add(proof, 0x1fc0))            mstore(add(transcript, 0x2140), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x1fe0))            mstore(add(transcript, 0x2160), x)            let y := mload(add(proof, 0x2000))            mstore(add(transcript, 0x2180), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2020))            mstore(add(transcript, 0x21a0), x)            let y := mload(add(proof, 0x2040))            mstore(add(transcript, 0x21c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2060))            mstore(add(transcript, 0x21e0), x)            let y := mload(add(proof, 0x2080))            mstore(add(transcript, 0x2200), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x20a0))            mstore(add(transcript, 0x2220), x)            let y := mload(add(proof, 0x20c0))            mstore(add(transcript, 0x2240), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x20e0))            mstore(add(transcript, 0x2260), x)            let y := mload(add(proof, 0x2100))            mstore(add(transcript, 0x2280), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2120))            mstore(add(transcript, 0x22a0), x)            let y := mload(add(proof, 0x2140))            mstore(add(transcript, 0x22c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2160))            mstore(add(transcript, 0x22e0), x)            let y := mload(add(proof, 0x2180))            mstore(add(transcript, 0x2300), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x21a0))            mstore(add(transcript, 0x2320), x)            let y := mload(add(proof, 0x21c0))            mstore(add(transcript, 0x2340), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x21e0))            mstore(add(transcript, 0x2360), x)            let y := mload(add(proof, 0x2200))            mstore(add(transcript, 0x2380), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2220))            mstore(add(transcript, 0x23a0), x)            let y := mload(add(proof, 0x2240))            mstore(add(transcript, 0x23c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2260))            mstore(add(transcript, 0x23e0), x)            let y := mload(add(proof, 0x2280))            mstore(add(transcript, 0x2400), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x22a0))            mstore(add(transcript, 0x2420), x)            let y := mload(add(proof, 0x22c0))            mstore(add(transcript, 0x2440), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x22e0))            mstore(add(transcript, 0x2460), x)            let y := mload(add(proof, 0x2300))            mstore(add(transcript, 0x2480), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2320))            mstore(add(transcript, 0x24a0), x)            let y := mload(add(proof, 0x2340))            mstore(add(transcript, 0x24c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2360))            mstore(add(transcript, 0x24e0), x)            let y := mload(add(proof, 0x2380))            mstore(add(transcript, 0x2500), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x23a0))            mstore(add(transcript, 0x2520), x)            let y := mload(add(proof, 0x23c0))            mstore(add(transcript, 0x2540), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x23e0))            mstore(add(transcript, 0x2560), x)            let y := mload(add(proof, 0x2400))            mstore(add(transcript, 0x2580), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2420))            mstore(add(transcript, 0x25a0), x)            let y := mload(add(proof, 0x2440))            mstore(add(transcript, 0x25c0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2460))            mstore(add(transcript, 0x25e0), x)            let y := mload(add(proof, 0x2480))            mstore(add(transcript, 0x2600), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x24a0))            mstore(add(transcript, 0x2620), x)            let y := mload(add(proof, 0x24c0))            mstore(add(transcript, 0x2640), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x24e0))            mstore(add(transcript, 0x2660), x)            let y := mload(add(proof, 0x2500))            mstore(add(transcript, 0x2680), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2520))            mstore(add(transcript, 0x26a0), x)            let y := mload(add(proof, 0x2540))            mstore(add(transcript, 0x26c0), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0x26e0), keccak256(add(transcript, 0x1c40), 2720))
{            let hash := mload(add(transcript, 0x26e0))            mstore(add(transcript, 0x2700), mod(hash, f_q))            mstore(add(transcript, 0x2720), hash)        }

        {            let x := mload(add(proof, 0x2560))            mstore(add(transcript, 0x2740), x)            let y := mload(add(proof, 0x2580))            mstore(add(transcript, 0x2760), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x25a0))            mstore(add(transcript, 0x2780), x)            let y := mload(add(proof, 0x25c0))            mstore(add(transcript, 0x27a0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x25e0))            mstore(add(transcript, 0x27c0), x)            let y := mload(add(proof, 0x2600))            mstore(add(transcript, 0x27e0), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2620))            mstore(add(transcript, 0x2800), x)            let y := mload(add(proof, 0x2640))            mstore(add(transcript, 0x2820), y)            success := and(validate_ec_point(x, y), success)        }

        {            let x := mload(add(proof, 0x2660))            mstore(add(transcript, 0x2840), x)            let y := mload(add(proof, 0x2680))            mstore(add(transcript, 0x2860), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0x2880), keccak256(add(transcript, 0x2720), 352))
{            let hash := mload(add(transcript, 0x2880))            mstore(add(transcript, 0x28a0), mod(hash, f_q))            mstore(add(transcript, 0x28c0), hash)        }
mstore(add(transcript, 0x28e0), mod(mload(add(proof, 0x26a0)), f_q))
mstore(add(transcript, 0x2900), mod(mload(add(proof, 0x26c0)), f_q))
mstore(add(transcript, 0x2920), mod(mload(add(proof, 0x26e0)), f_q))
mstore(add(transcript, 0x2940), mod(mload(add(proof, 0x2700)), f_q))
mstore(add(transcript, 0x2960), mod(mload(add(proof, 0x2720)), f_q))
mstore(add(transcript, 0x2980), mod(mload(add(proof, 0x2740)), f_q))
mstore(add(transcript, 0x29a0), mod(mload(add(proof, 0x2760)), f_q))
mstore(add(transcript, 0x29c0), mod(mload(add(proof, 0x2780)), f_q))
mstore(add(transcript, 0x29e0), mod(mload(add(proof, 0x27a0)), f_q))
mstore(add(transcript, 0x2a00), mod(mload(add(proof, 0x27c0)), f_q))
mstore(add(transcript, 0x2a20), mod(mload(add(proof, 0x27e0)), f_q))
mstore(add(transcript, 0x2a40), mod(mload(add(proof, 0x2800)), f_q))
mstore(add(transcript, 0x2a60), mod(mload(add(proof, 0x2820)), f_q))
mstore(add(transcript, 0x2a80), mod(mload(add(proof, 0x2840)), f_q))
mstore(add(transcript, 0x2aa0), mod(mload(add(proof, 0x2860)), f_q))
mstore(add(transcript, 0x2ac0), mod(mload(add(proof, 0x2880)), f_q))
mstore(add(transcript, 0x2ae0), mod(mload(add(proof, 0x28a0)), f_q))
mstore(add(transcript, 0x2b00), mod(mload(add(proof, 0x28c0)), f_q))
mstore(add(transcript, 0x2b20), mod(mload(add(proof, 0x28e0)), f_q))
mstore(add(transcript, 0x2b40), mod(mload(add(proof, 0x2900)), f_q))
mstore(add(transcript, 0x2b60), mod(mload(add(proof, 0x2920)), f_q))
mstore(add(transcript, 0x2b80), mod(mload(add(proof, 0x2940)), f_q))
mstore(add(transcript, 0x2ba0), mod(mload(add(proof, 0x2960)), f_q))
mstore(add(transcript, 0x2bc0), mod(mload(add(proof, 0x2980)), f_q))
mstore(add(transcript, 0x2be0), mod(mload(add(proof, 0x29a0)), f_q))
mstore(add(transcript, 0x2c00), mod(mload(add(proof, 0x29c0)), f_q))
mstore(add(transcript, 0x2c20), mod(mload(add(proof, 0x29e0)), f_q))
mstore(add(transcript, 0x2c40), mod(mload(add(proof, 0x2a00)), f_q))
mstore(add(transcript, 0x2c60), mod(mload(add(proof, 0x2a20)), f_q))
mstore(add(transcript, 0x2c80), mod(mload(add(proof, 0x2a40)), f_q))
mstore(add(transcript, 0x2ca0), mod(mload(add(proof, 0x2a60)), f_q))
mstore(add(transcript, 0x2cc0), mod(mload(add(proof, 0x2a80)), f_q))
mstore(add(transcript, 0x2ce0), mod(mload(add(proof, 0x2aa0)), f_q))
mstore(add(transcript, 0x2d00), mod(mload(add(proof, 0x2ac0)), f_q))
mstore(add(transcript, 0x2d20), mod(mload(add(proof, 0x2ae0)), f_q))
mstore(add(transcript, 0x2d40), mod(mload(add(proof, 0x2b00)), f_q))
mstore(add(transcript, 0x2d60), mod(mload(add(proof, 0x2b20)), f_q))
mstore(add(transcript, 0x2d80), mod(mload(add(proof, 0x2b40)), f_q))
mstore(add(transcript, 0x2da0), mod(mload(add(proof, 0x2b60)), f_q))
mstore(add(transcript, 0x2dc0), mod(mload(add(proof, 0x2b80)), f_q))
mstore(add(transcript, 0x2de0), mod(mload(add(proof, 0x2ba0)), f_q))
mstore(add(transcript, 0x2e00), mod(mload(add(proof, 0x2bc0)), f_q))
mstore(add(transcript, 0x2e20), mod(mload(add(proof, 0x2be0)), f_q))
mstore(add(transcript, 0x2e40), mod(mload(add(proof, 0x2c00)), f_q))
mstore(add(transcript, 0x2e60), mod(mload(add(proof, 0x2c20)), f_q))
mstore(add(transcript, 0x2e80), mod(mload(add(proof, 0x2c40)), f_q))
mstore(add(transcript, 0x2ea0), mod(mload(add(proof, 0x2c60)), f_q))
mstore(add(transcript, 0x2ec0), mod(mload(add(proof, 0x2c80)), f_q))
mstore(add(transcript, 0x2ee0), mod(mload(add(proof, 0x2ca0)), f_q))
mstore(add(transcript, 0x2f00), mod(mload(add(proof, 0x2cc0)), f_q))
mstore(add(transcript, 0x2f20), mod(mload(add(proof, 0x2ce0)), f_q))
mstore(add(transcript, 0x2f40), mod(mload(add(proof, 0x2d00)), f_q))
mstore(add(transcript, 0x2f60), mod(mload(add(proof, 0x2d20)), f_q))
mstore(add(transcript, 0x2f80), mod(mload(add(proof, 0x2d40)), f_q))
mstore(add(transcript, 0x2fa0), mod(mload(add(proof, 0x2d60)), f_q))
mstore(add(transcript, 0x2fc0), mod(mload(add(proof, 0x2d80)), f_q))
mstore(add(transcript, 0x2fe0), mod(mload(add(proof, 0x2da0)), f_q))
mstore(add(transcript, 0x3000), mod(mload(add(proof, 0x2dc0)), f_q))
mstore(add(transcript, 0x3020), mod(mload(add(proof, 0x2de0)), f_q))
mstore(add(transcript, 0x3040), mod(mload(add(proof, 0x2e00)), f_q))
mstore(add(transcript, 0x3060), mod(mload(add(proof, 0x2e20)), f_q))
mstore(add(transcript, 0x3080), mod(mload(add(proof, 0x2e40)), f_q))
mstore(add(transcript, 0x30a0), mod(mload(add(proof, 0x2e60)), f_q))
mstore(add(transcript, 0x30c0), mod(mload(add(proof, 0x2e80)), f_q))
mstore(add(transcript, 0x30e0), mod(mload(add(proof, 0x2ea0)), f_q))
mstore(add(transcript, 0x3100), mod(mload(add(proof, 0x2ec0)), f_q))
mstore(add(transcript, 0x3120), mod(mload(add(proof, 0x2ee0)), f_q))
mstore(add(transcript, 0x3140), mod(mload(add(proof, 0x2f00)), f_q))
mstore(add(transcript, 0x3160), mod(mload(add(proof, 0x2f20)), f_q))
mstore(add(transcript, 0x3180), mod(mload(add(proof, 0x2f40)), f_q))
mstore(add(transcript, 0x31a0), mod(mload(add(proof, 0x2f60)), f_q))
mstore(add(transcript, 0x31c0), mod(mload(add(proof, 0x2f80)), f_q))
mstore(add(transcript, 0x31e0), mod(mload(add(proof, 0x2fa0)), f_q))
mstore(add(transcript, 0x3200), mod(mload(add(proof, 0x2fc0)), f_q))
mstore(add(transcript, 0x3220), mod(mload(add(proof, 0x2fe0)), f_q))
mstore(add(transcript, 0x3240), mod(mload(add(proof, 0x3000)), f_q))
mstore(add(transcript, 0x3260), mod(mload(add(proof, 0x3020)), f_q))
mstore(add(transcript, 0x3280), mod(mload(add(proof, 0x3040)), f_q))
mstore(add(transcript, 0x32a0), mod(mload(add(proof, 0x3060)), f_q))
mstore(add(transcript, 0x32c0), mod(mload(add(proof, 0x3080)), f_q))
mstore(add(transcript, 0x32e0), mod(mload(add(proof, 0x30a0)), f_q))
mstore(add(transcript, 0x3300), mod(mload(add(proof, 0x30c0)), f_q))
mstore(add(transcript, 0x3320), mod(mload(add(proof, 0x30e0)), f_q))
mstore(add(transcript, 0x3340), mod(mload(add(proof, 0x3100)), f_q))
mstore(add(transcript, 0x3360), mod(mload(add(proof, 0x3120)), f_q))
mstore(add(transcript, 0x3380), mod(mload(add(proof, 0x3140)), f_q))
mstore(add(transcript, 0x33a0), mod(mload(add(proof, 0x3160)), f_q))
mstore(add(transcript, 0x33c0), mod(mload(add(proof, 0x3180)), f_q))
mstore(add(transcript, 0x33e0), mod(mload(add(proof, 0x31a0)), f_q))
mstore(add(transcript, 0x3400), mod(mload(add(proof, 0x31c0)), f_q))
mstore(add(transcript, 0x3420), mod(mload(add(proof, 0x31e0)), f_q))
mstore(add(transcript, 0x3440), mod(mload(add(proof, 0x3200)), f_q))
mstore(add(transcript, 0x3460), mod(mload(add(proof, 0x3220)), f_q))
mstore(add(transcript, 0x3480), mod(mload(add(proof, 0x3240)), f_q))
mstore(add(transcript, 0x34a0), mod(mload(add(proof, 0x3260)), f_q))
mstore(add(transcript, 0x34c0), mod(mload(add(proof, 0x3280)), f_q))
mstore(add(transcript, 0x34e0), mod(mload(add(proof, 0x32a0)), f_q))
mstore(add(transcript, 0x3500), mod(mload(add(proof, 0x32c0)), f_q))
mstore(add(transcript, 0x3520), mod(mload(add(proof, 0x32e0)), f_q))
mstore(add(transcript, 0x3540), mod(mload(add(proof, 0x3300)), f_q))
mstore(add(transcript, 0x3560), mod(mload(add(proof, 0x3320)), f_q))
mstore(add(transcript, 0x3580), mod(mload(add(proof, 0x3340)), f_q))
mstore(add(transcript, 0x35a0), mod(mload(add(proof, 0x3360)), f_q))
mstore(add(transcript, 0x35c0), mod(mload(add(proof, 0x3380)), f_q))
mstore(add(transcript, 0x35e0), mod(mload(add(proof, 0x33a0)), f_q))
mstore(add(transcript, 0x3600), mod(mload(add(proof, 0x33c0)), f_q))
mstore(add(transcript, 0x3620), mod(mload(add(proof, 0x33e0)), f_q))
mstore(add(transcript, 0x3640), mod(mload(add(proof, 0x3400)), f_q))
mstore(add(transcript, 0x3660), mod(mload(add(proof, 0x3420)), f_q))
mstore(add(transcript, 0x3680), mod(mload(add(proof, 0x3440)), f_q))
mstore(add(transcript, 0x36a0), mod(mload(add(proof, 0x3460)), f_q))
mstore(add(transcript, 0x36c0), mod(mload(add(proof, 0x3480)), f_q))
mstore(add(transcript, 0x36e0), mod(mload(add(proof, 0x34a0)), f_q))
mstore(add(transcript, 0x3700), mod(mload(add(proof, 0x34c0)), f_q))
mstore(add(transcript, 0x3720), mod(mload(add(proof, 0x34e0)), f_q))
mstore(add(transcript, 0x3740), mod(mload(add(proof, 0x3500)), f_q))
mstore(add(transcript, 0x3760), mod(mload(add(proof, 0x3520)), f_q))
mstore(add(transcript, 0x3780), mod(mload(add(proof, 0x3540)), f_q))
mstore(add(transcript, 0x37a0), mod(mload(add(proof, 0x3560)), f_q))
mstore(add(transcript, 0x37c0), mod(mload(add(proof, 0x3580)), f_q))
mstore(add(transcript, 0x37e0), mod(mload(add(proof, 0x35a0)), f_q))
mstore(add(transcript, 0x3800), mod(mload(add(proof, 0x35c0)), f_q))
mstore(add(transcript, 0x3820), mod(mload(add(proof, 0x35e0)), f_q))
mstore(add(transcript, 0x3840), mod(mload(add(proof, 0x3600)), f_q))
mstore(add(transcript, 0x3860), mod(mload(add(proof, 0x3620)), f_q))
mstore(add(transcript, 0x3880), mod(mload(add(proof, 0x3640)), f_q))
mstore(add(transcript, 0x38a0), mod(mload(add(proof, 0x3660)), f_q))
mstore(add(transcript, 0x38c0), mod(mload(add(proof, 0x3680)), f_q))
mstore(add(transcript, 0x38e0), mod(mload(add(proof, 0x36a0)), f_q))
mstore(add(transcript, 0x3900), mod(mload(add(proof, 0x36c0)), f_q))
mstore(add(transcript, 0x3920), mod(mload(add(proof, 0x36e0)), f_q))
mstore(add(transcript, 0x3940), mod(mload(add(proof, 0x3700)), f_q))
mstore(add(transcript, 0x3960), mod(mload(add(proof, 0x3720)), f_q))
mstore(add(transcript, 0x3980), mod(mload(add(proof, 0x3740)), f_q))
mstore(add(transcript, 0x39a0), mod(mload(add(proof, 0x3760)), f_q))
mstore(add(transcript, 0x39c0), mod(mload(add(proof, 0x3780)), f_q))
mstore(add(transcript, 0x39e0), mod(mload(add(proof, 0x37a0)), f_q))
mstore(add(transcript, 0x3a00), mod(mload(add(proof, 0x37c0)), f_q))
mstore(add(transcript, 0x3a20), mod(mload(add(proof, 0x37e0)), f_q))
mstore(add(transcript, 0x3a40), mod(mload(add(proof, 0x3800)), f_q))
mstore(add(transcript, 0x3a60), mod(mload(add(proof, 0x3820)), f_q))
mstore(add(transcript, 0x3a80), mod(mload(add(proof, 0x3840)), f_q))
mstore(add(transcript, 0x3aa0), mod(mload(add(proof, 0x3860)), f_q))
mstore(add(transcript, 0x3ac0), mod(mload(add(proof, 0x3880)), f_q))
mstore(add(transcript, 0x3ae0), mod(mload(add(proof, 0x38a0)), f_q))
mstore(add(transcript, 0x3b00), mod(mload(add(proof, 0x38c0)), f_q))
mstore(add(transcript, 0x3b20), mod(mload(add(proof, 0x38e0)), f_q))
mstore(add(transcript, 0x3b40), mod(mload(add(proof, 0x3900)), f_q))
mstore(add(transcript, 0x3b60), mod(mload(add(proof, 0x3920)), f_q))
mstore(add(transcript, 0x3b80), mod(mload(add(proof, 0x3940)), f_q))
mstore(add(transcript, 0x3ba0), mod(mload(add(proof, 0x3960)), f_q))
mstore(add(transcript, 0x3bc0), mod(mload(add(proof, 0x3980)), f_q))
mstore(add(transcript, 0x3be0), mod(mload(add(proof, 0x39a0)), f_q))
mstore(add(transcript, 0x3c00), mod(mload(add(proof, 0x39c0)), f_q))
mstore(add(transcript, 0x3c20), mod(mload(add(proof, 0x39e0)), f_q))
mstore(add(transcript, 0x3c40), mod(mload(add(proof, 0x3a00)), f_q))
mstore(add(transcript, 0x3c60), mod(mload(add(proof, 0x3a20)), f_q))
mstore(add(transcript, 0x3c80), mod(mload(add(proof, 0x3a40)), f_q))
mstore(add(transcript, 0x3ca0), mod(mload(add(proof, 0x3a60)), f_q))
mstore(add(transcript, 0x3cc0), mod(mload(add(proof, 0x3a80)), f_q))
mstore(add(transcript, 0x3ce0), mod(mload(add(proof, 0x3aa0)), f_q))
mstore(add(transcript, 0x3d00), mod(mload(add(proof, 0x3ac0)), f_q))
mstore(add(transcript, 0x3d20), mod(mload(add(proof, 0x3ae0)), f_q))
mstore(add(transcript, 0x3d40), mod(mload(add(proof, 0x3b00)), f_q))
mstore(add(transcript, 0x3d60), mod(mload(add(proof, 0x3b20)), f_q))
mstore(add(transcript, 0x3d80), mod(mload(add(proof, 0x3b40)), f_q))
mstore(add(transcript, 0x3da0), mod(mload(add(proof, 0x3b60)), f_q))
mstore(add(transcript, 0x3dc0), mod(mload(add(proof, 0x3b80)), f_q))
mstore(add(transcript, 0x3de0), mod(mload(add(proof, 0x3ba0)), f_q))
mstore(add(transcript, 0x3e00), mod(mload(add(proof, 0x3bc0)), f_q))
mstore(add(transcript, 0x3e20), mod(mload(add(proof, 0x3be0)), f_q))
mstore(add(transcript, 0x3e40), mod(mload(add(proof, 0x3c00)), f_q))
mstore(add(transcript, 0x3e60), mod(mload(add(proof, 0x3c20)), f_q))
mstore(add(transcript, 0x3e80), mod(mload(add(proof, 0x3c40)), f_q))
mstore(add(transcript, 0x3ea0), mod(mload(add(proof, 0x3c60)), f_q))
mstore(add(transcript, 0x3ec0), mod(mload(add(proof, 0x3c80)), f_q))
mstore(add(transcript, 0x3ee0), mod(mload(add(proof, 0x3ca0)), f_q))
mstore(add(transcript, 0x3f00), mod(mload(add(proof, 0x3cc0)), f_q))
mstore(add(transcript, 0x3f20), mod(mload(add(proof, 0x3ce0)), f_q))
mstore(add(transcript, 0x3f40), mod(mload(add(proof, 0x3d00)), f_q))
mstore(add(transcript, 0x3f60), mod(mload(add(proof, 0x3d20)), f_q))
mstore(add(transcript, 0x3f80), mod(mload(add(proof, 0x3d40)), f_q))
mstore(add(transcript, 0x3fa0), mod(mload(add(proof, 0x3d60)), f_q))
mstore(add(transcript, 0x3fc0), mod(mload(add(proof, 0x3d80)), f_q))
mstore(add(transcript, 0x3fe0), mod(mload(add(proof, 0x3da0)), f_q))
mstore(add(transcript, 0x4000), mod(mload(add(proof, 0x3dc0)), f_q))
mstore(add(transcript, 0x4020), mod(mload(add(proof, 0x3de0)), f_q))
mstore(add(transcript, 0x4040), mod(mload(add(proof, 0x3e00)), f_q))
mstore(add(transcript, 0x4060), mod(mload(add(proof, 0x3e20)), f_q))
mstore(add(transcript, 0x4080), mod(mload(add(proof, 0x3e40)), f_q))
mstore(add(transcript, 0x40a0), mod(mload(add(proof, 0x3e60)), f_q))
mstore(add(transcript, 0x40c0), mod(mload(add(proof, 0x3e80)), f_q))
mstore(add(transcript, 0x40e0), mod(mload(add(proof, 0x3ea0)), f_q))
mstore(add(transcript, 0x4100), mod(mload(add(proof, 0x3ec0)), f_q))
mstore(add(transcript, 0x4120), mod(mload(add(proof, 0x3ee0)), f_q))
mstore(add(transcript, 0x4140), mod(mload(add(proof, 0x3f00)), f_q))
mstore(add(transcript, 0x4160), mod(mload(add(proof, 0x3f20)), f_q))
mstore(add(transcript, 0x4180), mod(mload(add(proof, 0x3f40)), f_q))
mstore(add(transcript, 0x41a0), mod(mload(add(proof, 0x3f60)), f_q))
mstore(add(transcript, 0x41c0), mod(mload(add(proof, 0x3f80)), f_q))
mstore(add(transcript, 0x41e0), mod(mload(add(proof, 0x3fa0)), f_q))
mstore(add(transcript, 0x4200), mod(mload(add(proof, 0x3fc0)), f_q))
mstore(add(transcript, 0x4220), mod(mload(add(proof, 0x3fe0)), f_q))
mstore(add(transcript, 0x4240), mod(mload(add(proof, 0x4000)), f_q))
mstore(add(transcript, 0x4260), mod(mload(add(proof, 0x4020)), f_q))
mstore(add(transcript, 0x4280), mod(mload(add(proof, 0x4040)), f_q))
mstore(add(transcript, 0x42a0), mod(mload(add(proof, 0x4060)), f_q))
mstore(add(transcript, 0x42c0), mod(mload(add(proof, 0x4080)), f_q))
mstore(add(transcript, 0x42e0), mod(mload(add(proof, 0x40a0)), f_q))
mstore(add(transcript, 0x4300), mod(mload(add(proof, 0x40c0)), f_q))
mstore(add(transcript, 0x4320), mod(mload(add(proof, 0x40e0)), f_q))
mstore(add(transcript, 0x4340), mod(mload(add(proof, 0x4100)), f_q))
mstore(add(transcript, 0x4360), mod(mload(add(proof, 0x4120)), f_q))
mstore(add(transcript, 0x4380), mod(mload(add(proof, 0x4140)), f_q))
mstore(add(transcript, 0x43a0), mod(mload(add(proof, 0x4160)), f_q))
mstore(add(transcript, 0x43c0), mod(mload(add(proof, 0x4180)), f_q))
mstore(add(transcript, 0x43e0), mod(mload(add(proof, 0x41a0)), f_q))
mstore(add(transcript, 0x4400), mod(mload(add(proof, 0x41c0)), f_q))
mstore(add(transcript, 0x4420), mod(mload(add(proof, 0x41e0)), f_q))
mstore(add(transcript, 0x4440), mod(mload(add(proof, 0x4200)), f_q))
mstore(add(transcript, 0x4460), mod(mload(add(proof, 0x4220)), f_q))
mstore(add(transcript, 0x4480), mod(mload(add(proof, 0x4240)), f_q))
mstore(add(transcript, 0x44a0), mod(mload(add(proof, 0x4260)), f_q))
mstore(add(transcript, 0x44c0), mod(mload(add(proof, 0x4280)), f_q))
mstore(add(transcript, 0x44e0), mod(mload(add(proof, 0x42a0)), f_q))
mstore(add(transcript, 0x4500), mod(mload(add(proof, 0x42c0)), f_q))
mstore(add(transcript, 0x4520), mod(mload(add(proof, 0x42e0)), f_q))
mstore(add(transcript, 0x4540), mod(mload(add(proof, 0x4300)), f_q))
mstore(add(transcript, 0x4560), mod(mload(add(proof, 0x4320)), f_q))
mstore(add(transcript, 0x4580), mod(mload(add(proof, 0x4340)), f_q))
mstore(add(transcript, 0x45a0), mod(mload(add(proof, 0x4360)), f_q))
mstore(add(transcript, 0x45c0), mod(mload(add(proof, 0x4380)), f_q))
mstore(add(transcript, 0x45e0), mod(mload(add(proof, 0x43a0)), f_q))
mstore(add(transcript, 0x4600), mod(mload(add(proof, 0x43c0)), f_q))
mstore(add(transcript, 0x4620), mod(mload(add(proof, 0x43e0)), f_q))
mstore(add(transcript, 0x4640), mod(mload(add(proof, 0x4400)), f_q))
mstore(add(transcript, 0x4660), mod(mload(add(proof, 0x4420)), f_q))
mstore(add(transcript, 0x4680), mod(mload(add(proof, 0x4440)), f_q))
mstore(add(transcript, 0x46a0), mod(mload(add(proof, 0x4460)), f_q))
mstore(add(transcript, 0x46c0), mod(mload(add(proof, 0x4480)), f_q))
mstore(add(transcript, 0x46e0), mod(mload(add(proof, 0x44a0)), f_q))
mstore(add(transcript, 0x4700), mod(mload(add(proof, 0x44c0)), f_q))
mstore(add(transcript, 0x4720), mod(mload(add(proof, 0x44e0)), f_q))
mstore(add(transcript, 0x4740), mod(mload(add(proof, 0x4500)), f_q))
mstore(add(transcript, 0x4760), mod(mload(add(proof, 0x4520)), f_q))
mstore(add(transcript, 0x4780), mod(mload(add(proof, 0x4540)), f_q))
mstore(add(transcript, 0x47a0), mod(mload(add(proof, 0x4560)), f_q))
mstore(add(transcript, 0x47c0), mod(mload(add(proof, 0x4580)), f_q))
mstore(add(transcript, 0x47e0), mod(mload(add(proof, 0x45a0)), f_q))
mstore(add(transcript, 0x4800), mod(mload(add(proof, 0x45c0)), f_q))
mstore(add(transcript, 0x4820), mod(mload(add(proof, 0x45e0)), f_q))
mstore(add(transcript, 0x4840), mod(mload(add(proof, 0x4600)), f_q))
mstore(add(transcript, 0x4860), mod(mload(add(proof, 0x4620)), f_q))
mstore(add(transcript, 0x4880), mod(mload(add(proof, 0x4640)), f_q))
mstore(add(transcript, 0x48a0), mod(mload(add(proof, 0x4660)), f_q))
mstore(add(transcript, 0x48c0), mod(mload(add(proof, 0x4680)), f_q))
mstore(add(transcript, 0x48e0), mod(mload(add(proof, 0x46a0)), f_q))
mstore(add(transcript, 0x4900), mod(mload(add(proof, 0x46c0)), f_q))
mstore(add(transcript, 0x4920), mod(mload(add(proof, 0x46e0)), f_q))
mstore(add(transcript, 0x4940), mod(mload(add(proof, 0x4700)), f_q))
mstore(add(transcript, 0x4960), mod(mload(add(proof, 0x4720)), f_q))
mstore(add(transcript, 0x4980), mod(mload(add(proof, 0x4740)), f_q))
mstore(add(transcript, 0x49a0), mod(mload(add(proof, 0x4760)), f_q))
mstore(add(transcript, 0x49c0), mod(mload(add(proof, 0x4780)), f_q))
mstore(add(transcript, 0x49e0), mod(mload(add(proof, 0x47a0)), f_q))
mstore(add(transcript, 0x4a00), mod(mload(add(proof, 0x47c0)), f_q))
mstore(add(transcript, 0x4a20), mod(mload(add(proof, 0x47e0)), f_q))
mstore(add(transcript, 0x4a40), mod(mload(add(proof, 0x4800)), f_q))
mstore(add(transcript, 0x4a60), mod(mload(add(proof, 0x4820)), f_q))
mstore(add(transcript, 0x4a80), mod(mload(add(proof, 0x4840)), f_q))
mstore(add(transcript, 0x4aa0), mod(mload(add(proof, 0x4860)), f_q))
mstore(add(transcript, 0x4ac0), mod(mload(add(proof, 0x4880)), f_q))
mstore(add(transcript, 0x4ae0), mod(mload(add(proof, 0x48a0)), f_q))
mstore(add(transcript, 0x4b00), mod(mload(add(proof, 0x48c0)), f_q))
mstore(add(transcript, 0x4b20), mod(mload(add(proof, 0x48e0)), f_q))
mstore(add(transcript, 0x4b40), mod(mload(add(proof, 0x4900)), f_q))
mstore(add(transcript, 0x4b60), mod(mload(add(proof, 0x4920)), f_q))
mstore(add(transcript, 0x4b80), mod(mload(add(proof, 0x4940)), f_q))
mstore(add(transcript, 0x4ba0), mod(mload(add(proof, 0x4960)), f_q))
mstore(add(transcript, 0x4bc0), mod(mload(add(proof, 0x4980)), f_q))
mstore(add(transcript, 0x4be0), mod(mload(add(proof, 0x49a0)), f_q))
mstore(add(transcript, 0x4c00), mod(mload(add(proof, 0x49c0)), f_q))
mstore(add(transcript, 0x4c20), mod(mload(add(proof, 0x49e0)), f_q))
mstore(add(transcript, 0x4c40), mod(mload(add(proof, 0x4a00)), f_q))
mstore(add(transcript, 0x4c60), mod(mload(add(proof, 0x4a20)), f_q))
mstore(add(transcript, 0x4c80), mod(mload(add(proof, 0x4a40)), f_q))
mstore(add(transcript, 0x4ca0), mod(mload(add(proof, 0x4a60)), f_q))
mstore(add(transcript, 0x4cc0), mod(mload(add(proof, 0x4a80)), f_q))
mstore(add(transcript, 0x4ce0), mod(mload(add(proof, 0x4aa0)), f_q))
mstore(add(transcript, 0x4d00), mod(mload(add(proof, 0x4ac0)), f_q))
mstore(add(transcript, 0x4d20), mod(mload(add(proof, 0x4ae0)), f_q))
mstore(add(transcript, 0x4d40), mod(mload(add(proof, 0x4b00)), f_q))
mstore(add(transcript, 0x4d60), mod(mload(add(proof, 0x4b20)), f_q))
mstore(add(transcript, 0x4d80), mod(mload(add(proof, 0x4b40)), f_q))
mstore(add(transcript, 0x4da0), mod(mload(add(proof, 0x4b60)), f_q))
mstore(add(transcript, 0x4dc0), mod(mload(add(proof, 0x4b80)), f_q))
mstore(add(transcript, 0x4de0), mod(mload(add(proof, 0x4ba0)), f_q))
mstore(add(transcript, 0x4e00), mod(mload(add(proof, 0x4bc0)), f_q))
mstore(add(transcript, 0x4e20), mod(mload(add(proof, 0x4be0)), f_q))
mstore(add(transcript, 0x4e40), mod(mload(add(proof, 0x4c00)), f_q))
mstore(add(transcript, 0x4e60), mod(mload(add(proof, 0x4c20)), f_q))
mstore(add(transcript, 0x4e80), mod(mload(add(proof, 0x4c40)), f_q))
mstore(add(transcript, 0x4ea0), mod(mload(add(proof, 0x4c60)), f_q))
mstore(add(transcript, 0x4ec0), mod(mload(add(proof, 0x4c80)), f_q))
mstore(add(transcript, 0x4ee0), mod(mload(add(proof, 0x4ca0)), f_q))
mstore(add(transcript, 0x4f00), mod(mload(add(proof, 0x4cc0)), f_q))
mstore(add(transcript, 0x4f20), mod(mload(add(proof, 0x4ce0)), f_q))
mstore(add(transcript, 0x4f40), mod(mload(add(proof, 0x4d00)), f_q))
mstore(add(transcript, 0x4f60), mod(mload(add(proof, 0x4d20)), f_q))
mstore(add(transcript, 0x4f80), mod(mload(add(proof, 0x4d40)), f_q))
mstore(add(transcript, 0x4fa0), mod(mload(add(proof, 0x4d60)), f_q))
mstore(add(transcript, 0x4fc0), mod(mload(add(proof, 0x4d80)), f_q))
mstore(add(transcript, 0x4fe0), mod(mload(add(proof, 0x4da0)), f_q))
mstore(add(transcript, 0x5000), mod(mload(add(proof, 0x4dc0)), f_q))
mstore(add(transcript, 0x5020), mod(mload(add(proof, 0x4de0)), f_q))
mstore(add(transcript, 0x5040), mod(mload(add(proof, 0x4e00)), f_q))
mstore(add(transcript, 0x5060), mod(mload(add(proof, 0x4e20)), f_q))
mstore(add(transcript, 0x5080), mod(mload(add(proof, 0x4e40)), f_q))
mstore(add(transcript, 0x50a0), mod(mload(add(proof, 0x4e60)), f_q))
mstore(add(transcript, 0x50c0), mod(mload(add(proof, 0x4e80)), f_q))
mstore(add(transcript, 0x50e0), mod(mload(add(proof, 0x4ea0)), f_q))
mstore(add(transcript, 0x5100), mod(mload(add(proof, 0x4ec0)), f_q))
mstore(add(transcript, 0x5120), mod(mload(add(proof, 0x4ee0)), f_q))
mstore(add(transcript, 0x5140), mod(mload(add(proof, 0x4f00)), f_q))
mstore(add(transcript, 0x5160), mod(mload(add(proof, 0x4f20)), f_q))
mstore(add(transcript, 0x5180), mod(mload(add(proof, 0x4f40)), f_q))
mstore(add(transcript, 0x51a0), mod(mload(add(proof, 0x4f60)), f_q))
mstore(add(transcript, 0x51c0), mod(mload(add(proof, 0x4f80)), f_q))
mstore(add(transcript, 0x51e0), mod(mload(add(proof, 0x4fa0)), f_q))
mstore(add(transcript, 0x5200), mod(mload(add(proof, 0x4fc0)), f_q))
mstore(add(transcript, 0x5220), mod(mload(add(proof, 0x4fe0)), f_q))
mstore(add(transcript, 0x5240), mod(mload(add(proof, 0x5000)), f_q))
mstore(add(transcript, 0x5260), mod(mload(add(proof, 0x5020)), f_q))
mstore(add(transcript, 0x5280), mod(mload(add(proof, 0x5040)), f_q))
mstore(add(transcript, 0x52a0), mod(mload(add(proof, 0x5060)), f_q))
mstore(add(transcript, 0x52c0), mod(mload(add(proof, 0x5080)), f_q))
mstore(add(transcript, 0x52e0), mod(mload(add(proof, 0x50a0)), f_q))
mstore(add(transcript, 0x5300), mod(mload(add(proof, 0x50c0)), f_q))
mstore(add(transcript, 0x5320), mod(mload(add(proof, 0x50e0)), f_q))
mstore(add(transcript, 0x5340), mod(mload(add(proof, 0x5100)), f_q))
mstore(add(transcript, 0x5360), mod(mload(add(proof, 0x5120)), f_q))
mstore(add(transcript, 0x5380), mod(mload(add(proof, 0x5140)), f_q))
mstore(add(transcript, 0x53a0), mod(mload(add(proof, 0x5160)), f_q))
mstore(add(transcript, 0x53c0), mod(mload(add(proof, 0x5180)), f_q))
mstore(add(transcript, 0x53e0), mod(mload(add(proof, 0x51a0)), f_q))
mstore(add(transcript, 0x5400), mod(mload(add(proof, 0x51c0)), f_q))
mstore(add(transcript, 0x5420), mod(mload(add(proof, 0x51e0)), f_q))
mstore(add(transcript, 0x5440), mod(mload(add(proof, 0x5200)), f_q))
mstore(add(transcript, 0x5460), mod(mload(add(proof, 0x5220)), f_q))
mstore(add(transcript, 0x5480), mod(mload(add(proof, 0x5240)), f_q))
mstore(add(transcript, 0x54a0), mod(mload(add(proof, 0x5260)), f_q))
mstore(add(transcript, 0x54c0), mod(mload(add(proof, 0x5280)), f_q))
mstore(add(transcript, 0x54e0), mod(mload(add(proof, 0x52a0)), f_q))
mstore(add(transcript, 0x5500), mod(mload(add(proof, 0x52c0)), f_q))
mstore(add(transcript, 0x5520), mod(mload(add(proof, 0x52e0)), f_q))
mstore(add(transcript, 0x5540), mod(mload(add(proof, 0x5300)), f_q))
mstore(add(transcript, 0x5560), mod(mload(add(proof, 0x5320)), f_q))
mstore(add(transcript, 0x5580), mod(mload(add(proof, 0x5340)), f_q))
mstore(add(transcript, 0x55a0), mod(mload(add(proof, 0x5360)), f_q))
mstore(add(transcript, 0x55c0), mod(mload(add(proof, 0x5380)), f_q))
mstore(add(transcript, 0x55e0), mod(mload(add(proof, 0x53a0)), f_q))
mstore(add(transcript, 0x5600), mod(mload(add(proof, 0x53c0)), f_q))
mstore(add(transcript, 0x5620), mod(mload(add(proof, 0x53e0)), f_q))
mstore(add(transcript, 0x5640), mod(mload(add(proof, 0x5400)), f_q))
mstore(add(transcript, 0x5660), mod(mload(add(proof, 0x5420)), f_q))
mstore(add(transcript, 0x5680), mod(mload(add(proof, 0x5440)), f_q))
mstore(add(transcript, 0x56a0), mod(mload(add(proof, 0x5460)), f_q))
mstore(add(transcript, 0x56c0), mod(mload(add(proof, 0x5480)), f_q))
mstore(add(transcript, 0x56e0), mod(mload(add(proof, 0x54a0)), f_q))
mstore(add(transcript, 0x5700), mod(mload(add(proof, 0x54c0)), f_q))
mstore(add(transcript, 0x5720), mod(mload(add(proof, 0x54e0)), f_q))
mstore(add(transcript, 0x5740), mod(mload(add(proof, 0x5500)), f_q))
mstore(add(transcript, 0x5760), mod(mload(add(proof, 0x5520)), f_q))
mstore(add(transcript, 0x5780), mod(mload(add(proof, 0x5540)), f_q))
mstore(add(transcript, 0x57a0), mod(mload(add(proof, 0x5560)), f_q))
mstore(add(transcript, 0x57c0), mod(mload(add(proof, 0x5580)), f_q))
mstore(add(transcript, 0x57e0), mod(mload(add(proof, 0x55a0)), f_q))
mstore(add(transcript, 0x5800), mod(mload(add(proof, 0x55c0)), f_q))
mstore(add(transcript, 0x5820), mod(mload(add(proof, 0x55e0)), f_q))
mstore(add(transcript, 0x5840), mod(mload(add(proof, 0x5600)), f_q))
mstore(add(transcript, 0x5860), mod(mload(add(proof, 0x5620)), f_q))
mstore(add(transcript, 0x5880), mod(mload(add(proof, 0x5640)), f_q))
mstore(add(transcript, 0x58a0), mod(mload(add(proof, 0x5660)), f_q))
mstore(add(transcript, 0x58c0), mod(mload(add(proof, 0x5680)), f_q))
mstore(add(transcript, 0x58e0), mod(mload(add(proof, 0x56a0)), f_q))
mstore(add(transcript, 0x5900), mod(mload(add(proof, 0x56c0)), f_q))
mstore(add(transcript, 0x5920), mod(mload(add(proof, 0x56e0)), f_q))
mstore(add(transcript, 0x5940), mod(mload(add(proof, 0x5700)), f_q))
mstore(add(transcript, 0x5960), mod(mload(add(proof, 0x5720)), f_q))
mstore(add(transcript, 0x5980), mod(mload(add(proof, 0x5740)), f_q))
mstore(add(transcript, 0x59a0), mod(mload(add(proof, 0x5760)), f_q))
mstore(add(transcript, 0x59c0), mod(mload(add(proof, 0x5780)), f_q))
mstore(add(transcript, 0x59e0), mod(mload(add(proof, 0x57a0)), f_q))
mstore(add(transcript, 0x5a00), mod(mload(add(proof, 0x57c0)), f_q))
mstore(add(transcript, 0x5a20), mod(mload(add(proof, 0x57e0)), f_q))
mstore(add(transcript, 0x5a40), mod(mload(add(proof, 0x5800)), f_q))
mstore(add(transcript, 0x5a60), mod(mload(add(proof, 0x5820)), f_q))
mstore(add(transcript, 0x5a80), mod(mload(add(proof, 0x5840)), f_q))
mstore(add(transcript, 0x5aa0), mod(mload(add(proof, 0x5860)), f_q))
mstore(add(transcript, 0x5ac0), mod(mload(add(proof, 0x5880)), f_q))
mstore(add(transcript, 0x5ae0), mod(mload(add(proof, 0x58a0)), f_q))
mstore(add(transcript, 0x5b00), mod(mload(add(proof, 0x58c0)), f_q))
mstore(add(transcript, 0x5b20), mod(mload(add(proof, 0x58e0)), f_q))
mstore(add(transcript, 0x5b40), mod(mload(add(proof, 0x5900)), f_q))
mstore(add(transcript, 0x5b60), mod(mload(add(proof, 0x5920)), f_q))
mstore(add(transcript, 0x5b80), mod(mload(add(proof, 0x5940)), f_q))
mstore(add(transcript, 0x5ba0), mod(mload(add(proof, 0x5960)), f_q))
mstore(add(transcript, 0x5bc0), mod(mload(add(proof, 0x5980)), f_q))
mstore(add(transcript, 0x5be0), mod(mload(add(proof, 0x59a0)), f_q))
mstore(add(transcript, 0x5c00), mod(mload(add(proof, 0x59c0)), f_q))
mstore(add(transcript, 0x5c20), mod(mload(add(proof, 0x59e0)), f_q))
mstore(add(transcript, 0x5c40), mod(mload(add(proof, 0x5a00)), f_q))
mstore(add(transcript, 0x5c60), mod(mload(add(proof, 0x5a20)), f_q))
mstore(add(transcript, 0x5c80), mod(mload(add(proof, 0x5a40)), f_q))
mstore(add(transcript, 0x5ca0), mod(mload(add(proof, 0x5a60)), f_q))
mstore(add(transcript, 0x5cc0), mod(mload(add(proof, 0x5a80)), f_q))
mstore(add(transcript, 0x5ce0), mod(mload(add(proof, 0x5aa0)), f_q))
mstore(add(transcript, 0x5d00), mod(mload(add(proof, 0x5ac0)), f_q))
mstore(add(transcript, 0x5d20), mod(mload(add(proof, 0x5ae0)), f_q))
mstore(add(transcript, 0x5d40), mod(mload(add(proof, 0x5b00)), f_q))
mstore(add(transcript, 0x5d60), mod(mload(add(proof, 0x5b20)), f_q))
mstore(add(transcript, 0x5d80), mod(mload(add(proof, 0x5b40)), f_q))
mstore(add(transcript, 0x5da0), mod(mload(add(proof, 0x5b60)), f_q))
mstore(add(transcript, 0x5dc0), mod(mload(add(proof, 0x5b80)), f_q))
mstore(add(transcript, 0x5de0), mod(mload(add(proof, 0x5ba0)), f_q))
mstore(add(transcript, 0x5e00), mod(mload(add(proof, 0x5bc0)), f_q))
mstore(add(transcript, 0x5e20), mod(mload(add(proof, 0x5be0)), f_q))
mstore(add(transcript, 0x5e40), mod(mload(add(proof, 0x5c00)), f_q))
mstore(add(transcript, 0x5e60), mod(mload(add(proof, 0x5c20)), f_q))
mstore(add(transcript, 0x5e80), mod(mload(add(proof, 0x5c40)), f_q))
mstore(add(transcript, 0x5ea0), mod(mload(add(proof, 0x5c60)), f_q))
mstore(add(transcript, 0x5ec0), mod(mload(add(proof, 0x5c80)), f_q))
mstore(add(transcript, 0x5ee0), mod(mload(add(proof, 0x5ca0)), f_q))
mstore(add(transcript, 0x5f00), mod(mload(add(proof, 0x5cc0)), f_q))
mstore(add(transcript, 0x5f20), mod(mload(add(proof, 0x5ce0)), f_q))
mstore(add(transcript, 0x5f40), mod(mload(add(proof, 0x5d00)), f_q))
mstore(add(transcript, 0x5f60), mod(mload(add(proof, 0x5d20)), f_q))
mstore(add(transcript, 0x5f80), mod(mload(add(proof, 0x5d40)), f_q))
mstore(add(transcript, 0x5fa0), mod(mload(add(proof, 0x5d60)), f_q))
mstore(add(transcript, 0x5fc0), mod(mload(add(proof, 0x5d80)), f_q))
mstore(add(transcript, 0x5fe0), mod(mload(add(proof, 0x5da0)), f_q))
mstore(add(transcript, 0x6000), mod(mload(add(proof, 0x5dc0)), f_q))
mstore(add(transcript, 0x6020), mod(mload(add(proof, 0x5de0)), f_q))
mstore(add(transcript, 0x6040), mod(mload(add(proof, 0x5e00)), f_q))
mstore(add(transcript, 0x6060), mod(mload(add(proof, 0x5e20)), f_q))
mstore(add(transcript, 0x6080), mod(mload(add(proof, 0x5e40)), f_q))
mstore(add(transcript, 0x60a0), keccak256(add(transcript, 0x28c0), 14304))
{            let hash := mload(add(transcript, 0x60a0))            mstore(add(transcript, 0x60c0), mod(hash, f_q))            mstore(add(transcript, 0x60e0), hash)        }
mstore8(add(transcript, 0x6100), 1)
mstore(add(transcript, 0x6100), keccak256(add(transcript, 0x60e0), 33))
{            let hash := mload(add(transcript, 0x6100))            mstore(add(transcript, 0x6120), mod(hash, f_q))            mstore(add(transcript, 0x6140), hash)        }

        {            let x := mload(add(proof, 0x5e60))            mstore(add(transcript, 0x6160), x)            let y := mload(add(proof, 0x5e80))            mstore(add(transcript, 0x6180), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0x61a0), keccak256(add(transcript, 0x6140), 96))
{            let hash := mload(add(transcript, 0x61a0))            mstore(add(transcript, 0x61c0), mod(hash, f_q))            mstore(add(transcript, 0x61e0), hash)        }

        {            let x := mload(add(proof, 0x5ea0))            mstore(add(transcript, 0x6200), x)            let y := mload(add(proof, 0x5ec0))            mstore(add(transcript, 0x6220), y)            success := and(validate_ec_point(x, y), success)        }
mstore(add(transcript, 0x6240), mulmod(mload(add(transcript, 0x28a0)), mload(add(transcript, 0x28a0)), f_q))
mstore(add(transcript, 0x6260), mulmod(mload(add(transcript, 0x6240)), mload(add(transcript, 0x6240)), f_q))
mstore(add(transcript, 0x6280), mulmod(mload(add(transcript, 0x6260)), mload(add(transcript, 0x6260)), f_q))
mstore(add(transcript, 0x62a0), mulmod(mload(add(transcript, 0x6280)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x62c0), mulmod(mload(add(transcript, 0x62a0)), mload(add(transcript, 0x62a0)), f_q))
mstore(add(transcript, 0x62e0), mulmod(mload(add(transcript, 0x62c0)), mload(add(transcript, 0x62c0)), f_q))
mstore(add(transcript, 0x6300), mulmod(mload(add(transcript, 0x62e0)), mload(add(transcript, 0x62e0)), f_q))
mstore(add(transcript, 0x6320), mulmod(mload(add(transcript, 0x6300)), mload(add(transcript, 0x6300)), f_q))
mstore(add(transcript, 0x6340), mulmod(mload(add(transcript, 0x6320)), mload(add(transcript, 0x6320)), f_q))
mstore(add(transcript, 0x6360), mulmod(mload(add(transcript, 0x6340)), mload(add(transcript, 0x6340)), f_q))
mstore(add(transcript, 0x6380), mulmod(mload(add(transcript, 0x6360)), mload(add(transcript, 0x6360)), f_q))
mstore(add(transcript, 0x63a0), mulmod(mload(add(transcript, 0x6380)), mload(add(transcript, 0x6380)), f_q))
mstore(add(transcript, 0x63c0), mulmod(mload(add(transcript, 0x63a0)), mload(add(transcript, 0x63a0)), f_q))
mstore(add(transcript, 0x63e0), mulmod(mload(add(transcript, 0x63c0)), mload(add(transcript, 0x63c0)), f_q))
mstore(add(transcript, 0x6400), mulmod(mload(add(transcript, 0x63e0)), mload(add(transcript, 0x63e0)), f_q))
mstore(add(transcript, 0x6420), mulmod(mload(add(transcript, 0x6400)), mload(add(transcript, 0x6400)), f_q))
mstore(add(transcript, 0x6440), mulmod(mload(add(transcript, 0x6420)), mload(add(transcript, 0x6420)), f_q))
mstore(add(transcript, 0x6460), addmod(mload(add(transcript, 0x6440)), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q))
mstore(add(transcript, 0x6480), mulmod(mload(add(transcript, 0x6460)), 21888075877798810139885396174900942254113179552665176677420557563313886988289, f_q))
mstore(add(transcript, 0x64a0), mulmod(mload(add(transcript, 0x6480)), 21180393220728113421338195116216869725258066600961496947533653125588029756005, f_q))
mstore(add(transcript, 0x64c0), addmod(mload(add(transcript, 0x28a0)), 707849651111161800908210629040405363290297799454537396164551060987778739612, f_q))
mstore(add(transcript, 0x64e0), mulmod(mload(add(transcript, 0x6480)), 18801136258871406524726641978934912926273987048785013233465874845411408769764, f_q))
mstore(add(transcript, 0x6500), addmod(mload(add(transcript, 0x28a0)), 3087106612967868697519763766322362162274377351631021110232329341164399725853, f_q))
mstore(add(transcript, 0x6520), mulmod(mload(add(transcript, 0x6480)), 13137266746974929847674828718073699700748973485900204084410541910719500618841, f_q))
mstore(add(transcript, 0x6540), addmod(mload(add(transcript, 0x28a0)), 8750976124864345374571577027183575387799390914515830259287662275856307876776, f_q))
mstore(add(transcript, 0x6560), mulmod(mload(add(transcript, 0x6480)), 14204982954615820785730815556166377574172276341958019443243371773666809943588, f_q))
mstore(add(transcript, 0x6580), addmod(mload(add(transcript, 0x28a0)), 7683259917223454436515590189090897514376088058458014900454832412908998552029, f_q))
mstore(add(transcript, 0x65a0), mulmod(mload(add(transcript, 0x6480)), 9798514389911400568976296423560720718971335345616984532185711118739339214189, f_q))
mstore(add(transcript, 0x65c0), addmod(mload(add(transcript, 0x28a0)), 12089728481927874653270109321696554369577029054799049811512493067836469281428, f_q))
mstore(add(transcript, 0x65e0), mulmod(mload(add(transcript, 0x6480)), 5857228514216831962358810454360739186987616060007133076514874820078026801648, f_q))
mstore(add(transcript, 0x6600), addmod(mload(add(transcript, 0x28a0)), 16031014357622443259887595290896535901560748340408901267183329366497781693969, f_q))
mstore(add(transcript, 0x6620), mulmod(mload(add(transcript, 0x6480)), 11402394834529375719535454173347509224290498423785625657829583372803806900475, f_q))
mstore(add(transcript, 0x6640), addmod(mload(add(transcript, 0x28a0)), 10485848037309899502710951571909765864257865976630408685868620813772001595142, f_q))
mstore(add(transcript, 0x6660), mulmod(mload(add(transcript, 0x6480)), 1, f_q))
mstore(add(transcript, 0x6680), addmod(mload(add(transcript, 0x28a0)), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q))
mstore(add(transcript, 0x66a0), mulmod(mload(add(transcript, 0x6480)), 21846745818185811051373434299876022191132089169516983080959277716660228899818, f_q))
mstore(add(transcript, 0x66c0), addmod(mload(add(transcript, 0x28a0)), 41497053653464170872971445381252897416275230899051262738926469915579595799, f_q))
mstore(add(transcript, 0x66e0), mulmod(mload(add(transcript, 0x6480)), 4443263508319656594054352481848447997537391617204595126809744742387004492585, f_q))
mstore(add(transcript, 0x6700), addmod(mload(add(transcript, 0x28a0)), 17444979363519618628192053263408827091010972783211439216888459444188804003032, f_q))
{            let prod := mload(add(transcript, 0x64c0))                prod := mulmod(mload(add(transcript, 0x6500)), prod, f_q)                mstore(add(transcript, 0x6720), prod)                            prod := mulmod(mload(add(transcript, 0x6540)), prod, f_q)                mstore(add(transcript, 0x6740), prod)                            prod := mulmod(mload(add(transcript, 0x6580)), prod, f_q)                mstore(add(transcript, 0x6760), prod)                            prod := mulmod(mload(add(transcript, 0x65c0)), prod, f_q)                mstore(add(transcript, 0x6780), prod)                            prod := mulmod(mload(add(transcript, 0x6600)), prod, f_q)                mstore(add(transcript, 0x67a0), prod)                            prod := mulmod(mload(add(transcript, 0x6640)), prod, f_q)                mstore(add(transcript, 0x67c0), prod)                            prod := mulmod(mload(add(transcript, 0x6680)), prod, f_q)                mstore(add(transcript, 0x67e0), prod)                            prod := mulmod(mload(add(transcript, 0x66c0)), prod, f_q)                mstore(add(transcript, 0x6800), prod)                            prod := mulmod(mload(add(transcript, 0x6700)), prod, f_q)                mstore(add(transcript, 0x6820), prod)                            prod := mulmod(mload(add(transcript, 0x6460)), prod, f_q)                mstore(add(transcript, 0x6840), prod)                    }
mstore(add(transcript, 0x6880), 32)
mstore(add(transcript, 0x68a0), 32)
mstore(add(transcript, 0x68c0), 32)
mstore(add(transcript, 0x68e0), mload(add(transcript, 0x6840)))
mstore(add(transcript, 0x6900), 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(add(transcript, 0x6920), 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, add(transcript, 0x6880), 0xc0, add(transcript, 0x6860), 0x20), 1), success)
{                        let inv := mload(add(transcript, 0x6860))            let v                            v := mload(add(transcript, 0x6460))                    mstore(add(transcript, 0x6460), mulmod(mload(add(transcript, 0x6820)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x6700))                    mstore(add(transcript, 0x6700), mulmod(mload(add(transcript, 0x6800)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x66c0))                    mstore(add(transcript, 0x66c0), mulmod(mload(add(transcript, 0x67e0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x6680))                    mstore(add(transcript, 0x6680), mulmod(mload(add(transcript, 0x67c0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x6640))                    mstore(add(transcript, 0x6640), mulmod(mload(add(transcript, 0x67a0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x6600))                    mstore(add(transcript, 0x6600), mulmod(mload(add(transcript, 0x6780)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x65c0))                    mstore(add(transcript, 0x65c0), mulmod(mload(add(transcript, 0x6760)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x6580))                    mstore(add(transcript, 0x6580), mulmod(mload(add(transcript, 0x6740)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x6540))                    mstore(add(transcript, 0x6540), mulmod(mload(add(transcript, 0x6720)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x6500))                    mstore(add(transcript, 0x6500), mulmod(mload(add(transcript, 0x64c0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                mstore(add(transcript, 0x64c0), inv)        }
mstore(add(transcript, 0x6940), mulmod(mload(add(transcript, 0x64a0)), mload(add(transcript, 0x64c0)), f_q))
mstore(add(transcript, 0x6960), mulmod(mload(add(transcript, 0x64e0)), mload(add(transcript, 0x6500)), f_q))
mstore(add(transcript, 0x6980), mulmod(mload(add(transcript, 0x6520)), mload(add(transcript, 0x6540)), f_q))
mstore(add(transcript, 0x69a0), mulmod(mload(add(transcript, 0x6560)), mload(add(transcript, 0x6580)), f_q))
mstore(add(transcript, 0x69c0), mulmod(mload(add(transcript, 0x65a0)), mload(add(transcript, 0x65c0)), f_q))
mstore(add(transcript, 0x69e0), mulmod(mload(add(transcript, 0x65e0)), mload(add(transcript, 0x6600)), f_q))
mstore(add(transcript, 0x6a00), mulmod(mload(add(transcript, 0x6620)), mload(add(transcript, 0x6640)), f_q))
mstore(add(transcript, 0x6a20), mulmod(mload(add(transcript, 0x6660)), mload(add(transcript, 0x6680)), f_q))
mstore(add(transcript, 0x6a40), mulmod(mload(add(transcript, 0x66a0)), mload(add(transcript, 0x66c0)), f_q))
mstore(add(transcript, 0x6a60), mulmod(mload(add(transcript, 0x66e0)), mload(add(transcript, 0x6700)), f_q))
{            let result := mulmod(mload(add(transcript, 0x6a20)), mload(add(transcript, 0x20)), f_q)result := addmod(mulmod(mload(add(transcript, 0x6a40)), mload(add(transcript, 0x40)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x6a60)), mload(add(transcript, 0x60)), f_q), result, f_q)mstore(add(transcript, 0x6a80), result)        }
mstore(add(transcript, 0x6aa0), mulmod(mload(add(transcript, 0x2920)), mload(add(transcript, 0x2900)), f_q))
mstore(add(transcript, 0x6ac0), addmod(mload(add(transcript, 0x28e0)), mload(add(transcript, 0x6aa0)), f_q))
mstore(add(transcript, 0x6ae0), addmod(mload(add(transcript, 0x6ac0)), sub(f_q, mload(add(transcript, 0x2940))), f_q))
mstore(add(transcript, 0x6b00), mulmod(mload(add(transcript, 0x6ae0)), mload(add(transcript, 0x4100)), f_q))
mstore(add(transcript, 0x6b20), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x6b00)), f_q))
mstore(add(transcript, 0x6b40), mulmod(mload(add(transcript, 0x29a0)), mload(add(transcript, 0x2980)), f_q))
mstore(add(transcript, 0x6b60), addmod(mload(add(transcript, 0x2960)), mload(add(transcript, 0x6b40)), f_q))
mstore(add(transcript, 0x6b80), addmod(mload(add(transcript, 0x6b60)), sub(f_q, mload(add(transcript, 0x29c0))), f_q))
mstore(add(transcript, 0x6ba0), mulmod(mload(add(transcript, 0x6b80)), mload(add(transcript, 0x4120)), f_q))
mstore(add(transcript, 0x6bc0), addmod(mload(add(transcript, 0x6b20)), mload(add(transcript, 0x6ba0)), f_q))
mstore(add(transcript, 0x6be0), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x6bc0)), f_q))
mstore(add(transcript, 0x6c00), mulmod(mload(add(transcript, 0x2a20)), mload(add(transcript, 0x2a00)), f_q))
mstore(add(transcript, 0x6c20), addmod(mload(add(transcript, 0x29e0)), mload(add(transcript, 0x6c00)), f_q))
mstore(add(transcript, 0x6c40), addmod(mload(add(transcript, 0x6c20)), sub(f_q, mload(add(transcript, 0x2a40))), f_q))
mstore(add(transcript, 0x6c60), mulmod(mload(add(transcript, 0x6c40)), mload(add(transcript, 0x4140)), f_q))
mstore(add(transcript, 0x6c80), addmod(mload(add(transcript, 0x6be0)), mload(add(transcript, 0x6c60)), f_q))
mstore(add(transcript, 0x6ca0), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x6c80)), f_q))
mstore(add(transcript, 0x6cc0), mulmod(mload(add(transcript, 0x2aa0)), mload(add(transcript, 0x2a80)), f_q))
mstore(add(transcript, 0x6ce0), addmod(mload(add(transcript, 0x2a60)), mload(add(transcript, 0x6cc0)), f_q))
mstore(add(transcript, 0x6d00), addmod(mload(add(transcript, 0x6ce0)), sub(f_q, mload(add(transcript, 0x2ac0))), f_q))
mstore(add(transcript, 0x6d20), mulmod(mload(add(transcript, 0x6d00)), mload(add(transcript, 0x4160)), f_q))
mstore(add(transcript, 0x6d40), addmod(mload(add(transcript, 0x6ca0)), mload(add(transcript, 0x6d20)), f_q))
mstore(add(transcript, 0x6d60), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x6d40)), f_q))
mstore(add(transcript, 0x6d80), mulmod(mload(add(transcript, 0x2b20)), mload(add(transcript, 0x2b00)), f_q))
mstore(add(transcript, 0x6da0), addmod(mload(add(transcript, 0x2ae0)), mload(add(transcript, 0x6d80)), f_q))
mstore(add(transcript, 0x6dc0), addmod(mload(add(transcript, 0x6da0)), sub(f_q, mload(add(transcript, 0x2b40))), f_q))
mstore(add(transcript, 0x6de0), mulmod(mload(add(transcript, 0x6dc0)), mload(add(transcript, 0x4180)), f_q))
mstore(add(transcript, 0x6e00), addmod(mload(add(transcript, 0x6d60)), mload(add(transcript, 0x6de0)), f_q))
mstore(add(transcript, 0x6e20), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x6e00)), f_q))
mstore(add(transcript, 0x6e40), mulmod(mload(add(transcript, 0x2ba0)), mload(add(transcript, 0x2b80)), f_q))
mstore(add(transcript, 0x6e60), addmod(mload(add(transcript, 0x2b60)), mload(add(transcript, 0x6e40)), f_q))
mstore(add(transcript, 0x6e80), addmod(mload(add(transcript, 0x6e60)), sub(f_q, mload(add(transcript, 0x2bc0))), f_q))
mstore(add(transcript, 0x6ea0), mulmod(mload(add(transcript, 0x6e80)), mload(add(transcript, 0x41a0)), f_q))
mstore(add(transcript, 0x6ec0), addmod(mload(add(transcript, 0x6e20)), mload(add(transcript, 0x6ea0)), f_q))
mstore(add(transcript, 0x6ee0), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x6ec0)), f_q))
mstore(add(transcript, 0x6f00), mulmod(mload(add(transcript, 0x2c20)), mload(add(transcript, 0x2c00)), f_q))
mstore(add(transcript, 0x6f20), addmod(mload(add(transcript, 0x2be0)), mload(add(transcript, 0x6f00)), f_q))
mstore(add(transcript, 0x6f40), addmod(mload(add(transcript, 0x6f20)), sub(f_q, mload(add(transcript, 0x2c40))), f_q))
mstore(add(transcript, 0x6f60), mulmod(mload(add(transcript, 0x6f40)), mload(add(transcript, 0x41c0)), f_q))
mstore(add(transcript, 0x6f80), addmod(mload(add(transcript, 0x6ee0)), mload(add(transcript, 0x6f60)), f_q))
mstore(add(transcript, 0x6fa0), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x6f80)), f_q))
mstore(add(transcript, 0x6fc0), mulmod(mload(add(transcript, 0x2ca0)), mload(add(transcript, 0x2c80)), f_q))
mstore(add(transcript, 0x6fe0), addmod(mload(add(transcript, 0x2c60)), mload(add(transcript, 0x6fc0)), f_q))
mstore(add(transcript, 0x7000), addmod(mload(add(transcript, 0x6fe0)), sub(f_q, mload(add(transcript, 0x2cc0))), f_q))
mstore(add(transcript, 0x7020), mulmod(mload(add(transcript, 0x7000)), mload(add(transcript, 0x41e0)), f_q))
mstore(add(transcript, 0x7040), addmod(mload(add(transcript, 0x6fa0)), mload(add(transcript, 0x7020)), f_q))
mstore(add(transcript, 0x7060), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x7040)), f_q))
mstore(add(transcript, 0x7080), mulmod(mload(add(transcript, 0x2d20)), mload(add(transcript, 0x2d00)), f_q))
mstore(add(transcript, 0x70a0), addmod(mload(add(transcript, 0x2ce0)), mload(add(transcript, 0x7080)), f_q))
mstore(add(transcript, 0x70c0), addmod(mload(add(transcript, 0x70a0)), sub(f_q, mload(add(transcript, 0x2d40))), f_q))
mstore(add(transcript, 0x70e0), mulmod(mload(add(transcript, 0x70c0)), mload(add(transcript, 0x4200)), f_q))
mstore(add(transcript, 0x7100), addmod(mload(add(transcript, 0x7060)), mload(add(transcript, 0x70e0)), f_q))
mstore(add(transcript, 0x7120), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x7100)), f_q))
mstore(add(transcript, 0x7140), mulmod(mload(add(transcript, 0x2da0)), mload(add(transcript, 0x2d80)), f_q))
mstore(add(transcript, 0x7160), addmod(mload(add(transcript, 0x2d60)), mload(add(transcript, 0x7140)), f_q))
mstore(add(transcript, 0x7180), addmod(mload(add(transcript, 0x7160)), sub(f_q, mload(add(transcript, 0x2dc0))), f_q))
mstore(add(transcript, 0x71a0), mulmod(mload(add(transcript, 0x7180)), mload(add(transcript, 0x4220)), f_q))
mstore(add(transcript, 0x71c0), addmod(mload(add(transcript, 0x7120)), mload(add(transcript, 0x71a0)), f_q))
mstore(add(transcript, 0x71e0), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x71c0)), f_q))
mstore(add(transcript, 0x7200), mulmod(mload(add(transcript, 0x2e20)), mload(add(transcript, 0x2e00)), f_q))
mstore(add(transcript, 0x7220), addmod(mload(add(transcript, 0x2de0)), mload(add(transcript, 0x7200)), f_q))
mstore(add(transcript, 0x7240), addmod(mload(add(transcript, 0x7220)), sub(f_q, mload(add(transcript, 0x2e40))), f_q))
mstore(add(transcript, 0x7260), mulmod(mload(add(transcript, 0x7240)), mload(add(transcript, 0x4240)), f_q))
mstore(add(transcript, 0x7280), addmod(mload(add(transcript, 0x71e0)), mload(add(transcript, 0x7260)), f_q))
mstore(add(transcript, 0x72a0), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x7280)), f_q))
mstore(add(transcript, 0x72c0), mulmod(mload(add(transcript, 0x2ea0)), mload(add(transcript, 0x2e80)), f_q))
mstore(add(transcript, 0x72e0), addmod(mload(add(transcript, 0x2e60)), mload(add(transcript, 0x72c0)), f_q))
mstore(add(transcript, 0x7300), addmod(mload(add(transcript, 0x72e0)), sub(f_q, mload(add(transcript, 0x2ec0))), f_q))
mstore(add(transcript, 0x7320), mulmod(mload(add(transcript, 0x7300)), mload(add(transcript, 0x4260)), f_q))
mstore(add(transcript, 0x7340), addmod(mload(add(transcript, 0x72a0)), mload(add(transcript, 0x7320)), f_q))
mstore(add(transcript, 0x7360), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x7340)), f_q))
mstore(add(transcript, 0x7380), mulmod(mload(add(transcript, 0x2f20)), mload(add(transcript, 0x2f00)), f_q))
mstore(add(transcript, 0x73a0), addmod(mload(add(transcript, 0x2ee0)), mload(add(transcript, 0x7380)), f_q))
mstore(add(transcript, 0x73c0), addmod(mload(add(transcript, 0x73a0)), sub(f_q, mload(add(transcript, 0x2f40))), f_q))
mstore(add(transcript, 0x73e0), mulmod(mload(add(transcript, 0x73c0)), mload(add(transcript, 0x4280)), f_q))
mstore(add(transcript, 0x7400), addmod(mload(add(transcript, 0x7360)), mload(add(transcript, 0x73e0)), f_q))
mstore(add(transcript, 0x7420), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x7400)), f_q))
mstore(add(transcript, 0x7440), mulmod(mload(add(transcript, 0x2fa0)), mload(add(transcript, 0x2f80)), f_q))
mstore(add(transcript, 0x7460), addmod(mload(add(transcript, 0x2f60)), mload(add(transcript, 0x7440)), f_q))
mstore(add(transcript, 0x7480), addmod(mload(add(transcript, 0x7460)), sub(f_q, mload(add(transcript, 0x2fc0))), f_q))
mstore(add(transcript, 0x74a0), mulmod(mload(add(transcript, 0x7480)), mload(add(transcript, 0x42a0)), f_q))
mstore(add(transcript, 0x74c0), addmod(mload(add(transcript, 0x7420)), mload(add(transcript, 0x74a0)), f_q))
mstore(add(transcript, 0x74e0), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x74c0)), f_q))
mstore(add(transcript, 0x7500), mulmod(mload(add(transcript, 0x3020)), mload(add(transcript, 0x3000)), f_q))
mstore(add(transcript, 0x7520), addmod(mload(add(transcript, 0x2fe0)), mload(add(transcript, 0x7500)), f_q))
mstore(add(transcript, 0x7540), addmod(mload(add(transcript, 0x7520)), sub(f_q, mload(add(transcript, 0x3040))), f_q))
mstore(add(transcript, 0x7560), mulmod(mload(add(transcript, 0x7540)), mload(add(transcript, 0x42c0)), f_q))
mstore(add(transcript, 0x7580), addmod(mload(add(transcript, 0x74e0)), mload(add(transcript, 0x7560)), f_q))
mstore(add(transcript, 0x75a0), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x7580)), f_q))
mstore(add(transcript, 0x75c0), mulmod(mload(add(transcript, 0x30a0)), mload(add(transcript, 0x3080)), f_q))
mstore(add(transcript, 0x75e0), addmod(mload(add(transcript, 0x3060)), mload(add(transcript, 0x75c0)), f_q))
mstore(add(transcript, 0x7600), addmod(mload(add(transcript, 0x75e0)), sub(f_q, mload(add(transcript, 0x30c0))), f_q))
mstore(add(transcript, 0x7620), mulmod(mload(add(transcript, 0x7600)), mload(add(transcript, 0x42e0)), f_q))
mstore(add(transcript, 0x7640), addmod(mload(add(transcript, 0x75a0)), mload(add(transcript, 0x7620)), f_q))
mstore(add(transcript, 0x7660), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x7640)), f_q))
mstore(add(transcript, 0x7680), mulmod(mload(add(transcript, 0x3120)), mload(add(transcript, 0x3100)), f_q))
mstore(add(transcript, 0x76a0), addmod(mload(add(transcript, 0x30e0)), mload(add(transcript, 0x7680)), f_q))
mstore(add(transcript, 0x76c0), addmod(mload(add(transcript, 0x76a0)), sub(f_q, mload(add(transcript, 0x3140))), f_q))
mstore(add(transcript, 0x76e0), mulmod(mload(add(transcript, 0x76c0)), mload(add(transcript, 0x4300)), f_q))
mstore(add(transcript, 0x7700), addmod(mload(add(transcript, 0x7660)), mload(add(transcript, 0x76e0)), f_q))
mstore(add(transcript, 0x7720), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x7700)), f_q))
mstore(add(transcript, 0x7740), mulmod(mload(add(transcript, 0x33e0)), mload(add(transcript, 0x4060)), f_q))
mstore(add(transcript, 0x7760), addmod(1, sub(f_q, mload(add(transcript, 0x33e0))), f_q))
mstore(add(transcript, 0x7780), mulmod(mload(add(transcript, 0x7760)), mload(add(transcript, 0x7740)), f_q))
mstore(add(transcript, 0x77a0), addmod(mload(add(transcript, 0x7720)), mload(add(transcript, 0x7780)), f_q))
mstore(add(transcript, 0x77c0), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x77a0)), f_q))
mstore(add(transcript, 0x77e0), addmod(mload(add(transcript, 0x31c0)), 21888242871839275222246405745257275088548364400416034343698204186575808495617, f_q))
mstore(add(transcript, 0x7800), mulmod(mload(add(transcript, 0x77e0)), mload(add(transcript, 0x7740)), f_q))
mstore(add(transcript, 0x7820), addmod(mload(add(transcript, 0x77c0)), mload(add(transcript, 0x7800)), f_q))
mstore(add(transcript, 0x7840), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x7820)), f_q))
mstore(add(transcript, 0x7860), addmod(mload(add(transcript, 0x31e0)), 21888242871839275222246405745257275088548364400416034343698204186575808495617, f_q))
mstore(add(transcript, 0x7880), mulmod(mload(add(transcript, 0x7860)), mload(add(transcript, 0x7740)), f_q))
mstore(add(transcript, 0x78a0), addmod(mload(add(transcript, 0x7840)), mload(add(transcript, 0x7880)), f_q))
mstore(add(transcript, 0x78c0), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x78a0)), f_q))
mstore(add(transcript, 0x78e0), addmod(mload(add(transcript, 0x3200)), 21888242871839275222246405745257275088548364400416034343698204186575808495617, f_q))
mstore(add(transcript, 0x7900), mulmod(mload(add(transcript, 0x78e0)), mload(add(transcript, 0x7740)), f_q))
mstore(add(transcript, 0x7920), addmod(mload(add(transcript, 0x78c0)), mload(add(transcript, 0x7900)), f_q))
mstore(add(transcript, 0x7940), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x7920)), f_q))

        }}
        // bytes memory transcriptBytes = abi.encode(transcript);
        // bytes32[] memory newTranscript = new bytes32[](6992);
        // for(uint i=0; i<_transcript.length; i++) {
        //     newTranscript[i] = transcript[i];
        // }
        // require(newTranscript.length == 6992, "newTranscript length is not 6992");
        return (success, transcript);
    } 
}
