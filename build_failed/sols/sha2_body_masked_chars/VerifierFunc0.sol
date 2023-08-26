// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "../VerifierFuncAbst.sol";

contract VerifierFunc0 is VerifierFuncAbst {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes memory _transcript
    ) public view override returns (bool, bytes memory) {
        bytes32[1323] memory transcript;
        // require(_transcript.length == 1323, "transcript length is not 1323");
        if (_transcript.length != 0) {
            transcript = abi.decode(_transcript, (bytes32[1323]));
        }
        // for(uint i=0; i<_transcript.length; i++) {
        //     transcript[i] = _transcript[i];
        // }
        assembly {
            {
                let
                    f_p
                := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                let
                    f_q
                := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                function validate_ec_point(x, y) -> valid {
                    {
                        let x_lt_p := lt(
                            x,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        let y_lt_p := lt(
                            y,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        valid := and(x_lt_p, y_lt_p)
                    }
                    {
                        let x_is_zero := eq(x, 0)
                        let y_is_zero := eq(y, 0)
                        let x_or_y_is_zero := or(x_is_zero, y_is_zero)
                        let x_and_y_is_not_zero := not(x_or_y_is_zero)
                        valid := and(x_and_y_is_not_zero, valid)
                    }
                    {
                        let y_square := mulmod(
                            y,
                            y,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        let x_square := mulmod(
                            x,
                            x,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        let x_cube := mulmod(
                            x_square,
                            x,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        let x_cube_plus_3 := addmod(
                            x_cube,
                            3,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        let y_square_eq_x_cube_plus_3 := eq(
                            x_cube_plus_3,
                            y_square
                        )
                        valid := and(y_square_eq_x_cube_plus_3, valid)
                    }
                }
                mstore(
                    add(transcript, 0x20),
                    mod(mload(add(pubInputs, 0x20)), f_q)
                )
                mstore(
                    add(transcript, 0x40),
                    mod(mload(add(pubInputs, 0x40)), f_q)
                )
                mstore(
                    add(transcript, 0x60),
                    mod(mload(add(pubInputs, 0x60)), f_q)
                )
                mstore(
                    add(transcript, 0x0),
                    13140111254569824321448476375683005243101623394300703550683771461086755684194
                )

                {
                    let x := mload(add(proof, 0x20))
                    mstore(add(transcript, 0x80), x)
                    let y := mload(add(proof, 0x40))
                    mstore(add(transcript, 0xa0), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x60))
                    mstore(add(transcript, 0xc0), x)
                    let y := mload(add(proof, 0x80))
                    mstore(add(transcript, 0xe0), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0xa0))
                    mstore(add(transcript, 0x100), x)
                    let y := mload(add(proof, 0xc0))
                    mstore(add(transcript, 0x120), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0xe0))
                    mstore(add(transcript, 0x140), x)
                    let y := mload(add(proof, 0x100))
                    mstore(add(transcript, 0x160), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x120))
                    mstore(add(transcript, 0x180), x)
                    let y := mload(add(proof, 0x140))
                    mstore(add(transcript, 0x1a0), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x160))
                    mstore(add(transcript, 0x1c0), x)
                    let y := mload(add(proof, 0x180))
                    mstore(add(transcript, 0x1e0), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x1a0))
                    mstore(add(transcript, 0x200), x)
                    let y := mload(add(proof, 0x1c0))
                    mstore(add(transcript, 0x220), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x1e0))
                    mstore(add(transcript, 0x240), x)
                    let y := mload(add(proof, 0x200))
                    mstore(add(transcript, 0x260), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x220))
                    mstore(add(transcript, 0x280), x)
                    let y := mload(add(proof, 0x240))
                    mstore(add(transcript, 0x2a0), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x260))
                    mstore(add(transcript, 0x2c0), x)
                    let y := mload(add(proof, 0x280))
                    mstore(add(transcript, 0x2e0), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x2a0))
                    mstore(add(transcript, 0x300), x)
                    let y := mload(add(proof, 0x2c0))
                    mstore(add(transcript, 0x320), y)
                    success := and(validate_ec_point(x, y), success)
                }
                mstore(
                    add(transcript, 0x340),
                    keccak256(add(transcript, 0x0), 832)
                )
                {
                    let hash := mload(add(transcript, 0x340))
                    mstore(add(transcript, 0x360), mod(hash, f_q))
                    mstore(add(transcript, 0x380), hash)
                }

                {
                    let x := mload(add(proof, 0x2e0))
                    mstore(add(transcript, 0x3a0), x)
                    let y := mload(add(proof, 0x300))
                    mstore(add(transcript, 0x3c0), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x320))
                    mstore(add(transcript, 0x3e0), x)
                    let y := mload(add(proof, 0x340))
                    mstore(add(transcript, 0x400), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x360))
                    mstore(add(transcript, 0x420), x)
                    let y := mload(add(proof, 0x380))
                    mstore(add(transcript, 0x440), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x3a0))
                    mstore(add(transcript, 0x460), x)
                    let y := mload(add(proof, 0x3c0))
                    mstore(add(transcript, 0x480), y)
                    success := and(validate_ec_point(x, y), success)
                }
                mstore(
                    add(transcript, 0x4a0),
                    keccak256(add(transcript, 0x380), 288)
                )
                {
                    let hash := mload(add(transcript, 0x4a0))
                    mstore(add(transcript, 0x4c0), mod(hash, f_q))
                    mstore(add(transcript, 0x4e0), hash)
                }
                mstore8(add(transcript, 0x500), 1)
                mstore(
                    add(transcript, 0x500),
                    keccak256(add(transcript, 0x4e0), 33)
                )
                {
                    let hash := mload(add(transcript, 0x500))
                    mstore(add(transcript, 0x520), mod(hash, f_q))
                    mstore(add(transcript, 0x540), hash)
                }

                {
                    let x := mload(add(proof, 0x3e0))
                    mstore(add(transcript, 0x560), x)
                    let y := mload(add(proof, 0x400))
                    mstore(add(transcript, 0x580), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x420))
                    mstore(add(transcript, 0x5a0), x)
                    let y := mload(add(proof, 0x440))
                    mstore(add(transcript, 0x5c0), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x460))
                    mstore(add(transcript, 0x5e0), x)
                    let y := mload(add(proof, 0x480))
                    mstore(add(transcript, 0x600), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x4a0))
                    mstore(add(transcript, 0x620), x)
                    let y := mload(add(proof, 0x4c0))
                    mstore(add(transcript, 0x640), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x4e0))
                    mstore(add(transcript, 0x660), x)
                    let y := mload(add(proof, 0x500))
                    mstore(add(transcript, 0x680), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x520))
                    mstore(add(transcript, 0x6a0), x)
                    let y := mload(add(proof, 0x540))
                    mstore(add(transcript, 0x6c0), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x560))
                    mstore(add(transcript, 0x6e0), x)
                    let y := mload(add(proof, 0x580))
                    mstore(add(transcript, 0x700), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x5a0))
                    mstore(add(transcript, 0x720), x)
                    let y := mload(add(proof, 0x5c0))
                    mstore(add(transcript, 0x740), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x5e0))
                    mstore(add(transcript, 0x760), x)
                    let y := mload(add(proof, 0x600))
                    mstore(add(transcript, 0x780), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x620))
                    mstore(add(transcript, 0x7a0), x)
                    let y := mload(add(proof, 0x640))
                    mstore(add(transcript, 0x7c0), y)
                    success := and(validate_ec_point(x, y), success)
                }
                mstore(
                    add(transcript, 0x7e0),
                    keccak256(add(transcript, 0x540), 672)
                )
                {
                    let hash := mload(add(transcript, 0x7e0))
                    mstore(add(transcript, 0x800), mod(hash, f_q))
                    mstore(add(transcript, 0x820), hash)
                }

                {
                    let x := mload(add(proof, 0x660))
                    mstore(add(transcript, 0x840), x)
                    let y := mload(add(proof, 0x680))
                    mstore(add(transcript, 0x860), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x6a0))
                    mstore(add(transcript, 0x880), x)
                    let y := mload(add(proof, 0x6c0))
                    mstore(add(transcript, 0x8a0), y)
                    success := and(validate_ec_point(x, y), success)
                }

                {
                    let x := mload(add(proof, 0x6e0))
                    mstore(add(transcript, 0x8c0), x)
                    let y := mload(add(proof, 0x700))
                    mstore(add(transcript, 0x8e0), y)
                    success := and(validate_ec_point(x, y), success)
                }
                mstore(
                    add(transcript, 0x900),
                    keccak256(add(transcript, 0x820), 224)
                )
                {
                    let hash := mload(add(transcript, 0x900))
                    mstore(add(transcript, 0x920), mod(hash, f_q))
                    mstore(add(transcript, 0x940), hash)
                }
                mstore(
                    add(transcript, 0x960),
                    mod(mload(add(proof, 0x720)), f_q)
                )
                mstore(
                    add(transcript, 0x980),
                    mod(mload(add(proof, 0x740)), f_q)
                )
                mstore(
                    add(transcript, 0x9a0),
                    mod(mload(add(proof, 0x760)), f_q)
                )
                mstore(
                    add(transcript, 0x9c0),
                    mod(mload(add(proof, 0x780)), f_q)
                )
                mstore(
                    add(transcript, 0x9e0),
                    mod(mload(add(proof, 0x7a0)), f_q)
                )
                mstore(
                    add(transcript, 0xa00),
                    mod(mload(add(proof, 0x7c0)), f_q)
                )
                mstore(
                    add(transcript, 0xa20),
                    mod(mload(add(proof, 0x7e0)), f_q)
                )
                mstore(
                    add(transcript, 0xa40),
                    mod(mload(add(proof, 0x800)), f_q)
                )
                mstore(
                    add(transcript, 0xa60),
                    mod(mload(add(proof, 0x820)), f_q)
                )
                mstore(
                    add(transcript, 0xa80),
                    mod(mload(add(proof, 0x840)), f_q)
                )
                mstore(
                    add(transcript, 0xaa0),
                    mod(mload(add(proof, 0x860)), f_q)
                )
                mstore(
                    add(transcript, 0xac0),
                    mod(mload(add(proof, 0x880)), f_q)
                )
                mstore(
                    add(transcript, 0xae0),
                    mod(mload(add(proof, 0x8a0)), f_q)
                )
                mstore(
                    add(transcript, 0xb00),
                    mod(mload(add(proof, 0x8c0)), f_q)
                )
                mstore(
                    add(transcript, 0xb20),
                    mod(mload(add(proof, 0x8e0)), f_q)
                )
                mstore(
                    add(transcript, 0xb40),
                    mod(mload(add(proof, 0x900)), f_q)
                )
                mstore(
                    add(transcript, 0xb60),
                    mod(mload(add(proof, 0x920)), f_q)
                )
                mstore(
                    add(transcript, 0xb80),
                    mod(mload(add(proof, 0x940)), f_q)
                )
                mstore(
                    add(transcript, 0xba0),
                    mod(mload(add(proof, 0x960)), f_q)
                )
                mstore(
                    add(transcript, 0xbc0),
                    mod(mload(add(proof, 0x980)), f_q)
                )
                mstore(
                    add(transcript, 0xbe0),
                    mod(mload(add(proof, 0x9a0)), f_q)
                )
                mstore(
                    add(transcript, 0xc00),
                    mod(mload(add(proof, 0x9c0)), f_q)
                )
                mstore(
                    add(transcript, 0xc20),
                    mod(mload(add(proof, 0x9e0)), f_q)
                )
                mstore(
                    add(transcript, 0xc40),
                    mod(mload(add(proof, 0xa00)), f_q)
                )
                mstore(
                    add(transcript, 0xc60),
                    mod(mload(add(proof, 0xa20)), f_q)
                )
                mstore(
                    add(transcript, 0xc80),
                    mod(mload(add(proof, 0xa40)), f_q)
                )
                mstore(
                    add(transcript, 0xca0),
                    mod(mload(add(proof, 0xa60)), f_q)
                )
                mstore(
                    add(transcript, 0xcc0),
                    mod(mload(add(proof, 0xa80)), f_q)
                )
                mstore(
                    add(transcript, 0xce0),
                    mod(mload(add(proof, 0xaa0)), f_q)
                )
                mstore(
                    add(transcript, 0xd00),
                    mod(mload(add(proof, 0xac0)), f_q)
                )
                mstore(
                    add(transcript, 0xd20),
                    mod(mload(add(proof, 0xae0)), f_q)
                )
                mstore(
                    add(transcript, 0xd40),
                    mod(mload(add(proof, 0xb00)), f_q)
                )
                mstore(
                    add(transcript, 0xd60),
                    mod(mload(add(proof, 0xb20)), f_q)
                )
                mstore(
                    add(transcript, 0xd80),
                    mod(mload(add(proof, 0xb40)), f_q)
                )
                mstore(
                    add(transcript, 0xda0),
                    mod(mload(add(proof, 0xb60)), f_q)
                )
                mstore(
                    add(transcript, 0xdc0),
                    mod(mload(add(proof, 0xb80)), f_q)
                )
                mstore(
                    add(transcript, 0xde0),
                    mod(mload(add(proof, 0xba0)), f_q)
                )
                mstore(
                    add(transcript, 0xe00),
                    mod(mload(add(proof, 0xbc0)), f_q)
                )
                mstore(
                    add(transcript, 0xe20),
                    mod(mload(add(proof, 0xbe0)), f_q)
                )
                mstore(
                    add(transcript, 0xe40),
                    mod(mload(add(proof, 0xc00)), f_q)
                )
                mstore(
                    add(transcript, 0xe60),
                    mod(mload(add(proof, 0xc20)), f_q)
                )
                mstore(
                    add(transcript, 0xe80),
                    mod(mload(add(proof, 0xc40)), f_q)
                )
                mstore(
                    add(transcript, 0xea0),
                    mod(mload(add(proof, 0xc60)), f_q)
                )
                mstore(
                    add(transcript, 0xec0),
                    mod(mload(add(proof, 0xc80)), f_q)
                )
                mstore(
                    add(transcript, 0xee0),
                    mod(mload(add(proof, 0xca0)), f_q)
                )
                mstore(
                    add(transcript, 0xf00),
                    mod(mload(add(proof, 0xcc0)), f_q)
                )
                mstore(
                    add(transcript, 0xf20),
                    mod(mload(add(proof, 0xce0)), f_q)
                )
                mstore(
                    add(transcript, 0xf40),
                    mod(mload(add(proof, 0xd00)), f_q)
                )
                mstore(
                    add(transcript, 0xf60),
                    mod(mload(add(proof, 0xd20)), f_q)
                )
                mstore(
                    add(transcript, 0xf80),
                    mod(mload(add(proof, 0xd40)), f_q)
                )
                mstore(
                    add(transcript, 0xfa0),
                    mod(mload(add(proof, 0xd60)), f_q)
                )
                mstore(
                    add(transcript, 0xfc0),
                    mod(mload(add(proof, 0xd80)), f_q)
                )
                mstore(
                    add(transcript, 0xfe0),
                    mod(mload(add(proof, 0xda0)), f_q)
                )
                mstore(
                    add(transcript, 0x1000),
                    mod(mload(add(proof, 0xdc0)), f_q)
                )
                mstore(
                    add(transcript, 0x1020),
                    mod(mload(add(proof, 0xde0)), f_q)
                )
                mstore(
                    add(transcript, 0x1040),
                    mod(mload(add(proof, 0xe00)), f_q)
                )
                mstore(
                    add(transcript, 0x1060),
                    mod(mload(add(proof, 0xe20)), f_q)
                )
                mstore(
                    add(transcript, 0x1080),
                    mod(mload(add(proof, 0xe40)), f_q)
                )
                mstore(
                    add(transcript, 0x10a0),
                    mod(mload(add(proof, 0xe60)), f_q)
                )
                mstore(
                    add(transcript, 0x10c0),
                    mod(mload(add(proof, 0xe80)), f_q)
                )
                mstore(
                    add(transcript, 0x10e0),
                    mod(mload(add(proof, 0xea0)), f_q)
                )
                mstore(
                    add(transcript, 0x1100),
                    mod(mload(add(proof, 0xec0)), f_q)
                )
                mstore(
                    add(transcript, 0x1120),
                    mod(mload(add(proof, 0xee0)), f_q)
                )
                mstore(
                    add(transcript, 0x1140),
                    mod(mload(add(proof, 0xf00)), f_q)
                )
                mstore(
                    add(transcript, 0x1160),
                    mod(mload(add(proof, 0xf20)), f_q)
                )
                mstore(
                    add(transcript, 0x1180),
                    mod(mload(add(proof, 0xf40)), f_q)
                )
                mstore(
                    add(transcript, 0x11a0),
                    mod(mload(add(proof, 0xf60)), f_q)
                )
                mstore(
                    add(transcript, 0x11c0),
                    mod(mload(add(proof, 0xf80)), f_q)
                )
                mstore(
                    add(transcript, 0x11e0),
                    mod(mload(add(proof, 0xfa0)), f_q)
                )
                mstore(
                    add(transcript, 0x1200),
                    mod(mload(add(proof, 0xfc0)), f_q)
                )
                mstore(
                    add(transcript, 0x1220),
                    mod(mload(add(proof, 0xfe0)), f_q)
                )
                mstore(
                    add(transcript, 0x1240),
                    mod(mload(add(proof, 0x1000)), f_q)
                )
                mstore(
                    add(transcript, 0x1260),
                    mod(mload(add(proof, 0x1020)), f_q)
                )
                mstore(
                    add(transcript, 0x1280),
                    mod(mload(add(proof, 0x1040)), f_q)
                )
                mstore(
                    add(transcript, 0x12a0),
                    mod(mload(add(proof, 0x1060)), f_q)
                )
                mstore(
                    add(transcript, 0x12c0),
                    mod(mload(add(proof, 0x1080)), f_q)
                )
                mstore(
                    add(transcript, 0x12e0),
                    mod(mload(add(proof, 0x10a0)), f_q)
                )
                mstore(
                    add(transcript, 0x1300),
                    mod(mload(add(proof, 0x10c0)), f_q)
                )
                mstore(
                    add(transcript, 0x1320),
                    mod(mload(add(proof, 0x10e0)), f_q)
                )
                mstore(
                    add(transcript, 0x1340),
                    mod(mload(add(proof, 0x1100)), f_q)
                )
                mstore(
                    add(transcript, 0x1360),
                    mod(mload(add(proof, 0x1120)), f_q)
                )
                mstore(
                    add(transcript, 0x1380),
                    mod(mload(add(proof, 0x1140)), f_q)
                )
                mstore(
                    add(transcript, 0x13a0),
                    mod(mload(add(proof, 0x1160)), f_q)
                )
                mstore(
                    add(transcript, 0x13c0),
                    mod(mload(add(proof, 0x1180)), f_q)
                )
                mstore(
                    add(transcript, 0x13e0),
                    mod(mload(add(proof, 0x11a0)), f_q)
                )
                mstore(
                    add(transcript, 0x1400),
                    mod(mload(add(proof, 0x11c0)), f_q)
                )
                mstore(
                    add(transcript, 0x1420),
                    mod(mload(add(proof, 0x11e0)), f_q)
                )
                mstore(
                    add(transcript, 0x1440),
                    keccak256(add(transcript, 0x940), 2816)
                )
                {
                    let hash := mload(add(transcript, 0x1440))
                    mstore(add(transcript, 0x1460), mod(hash, f_q))
                    mstore(add(transcript, 0x1480), hash)
                }
                mstore8(add(transcript, 0x14a0), 1)
                mstore(
                    add(transcript, 0x14a0),
                    keccak256(add(transcript, 0x1480), 33)
                )
                {
                    let hash := mload(add(transcript, 0x14a0))
                    mstore(add(transcript, 0x14c0), mod(hash, f_q))
                    mstore(add(transcript, 0x14e0), hash)
                }

                {
                    let x := mload(add(proof, 0x1200))
                    mstore(add(transcript, 0x1500), x)
                    let y := mload(add(proof, 0x1220))
                    mstore(add(transcript, 0x1520), y)
                    success := and(validate_ec_point(x, y), success)
                }
                mstore(
                    add(transcript, 0x1540),
                    keccak256(add(transcript, 0x14e0), 96)
                )
                {
                    let hash := mload(add(transcript, 0x1540))
                    mstore(add(transcript, 0x1560), mod(hash, f_q))
                    mstore(add(transcript, 0x1580), hash)
                }

                {
                    let x := mload(add(proof, 0x1240))
                    mstore(add(transcript, 0x15a0), x)
                    let y := mload(add(proof, 0x1260))
                    mstore(add(transcript, 0x15c0), y)
                    success := and(validate_ec_point(x, y), success)
                }
                mstore(
                    add(transcript, 0x15e0),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x920)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1600),
                    mulmod(
                        mload(add(transcript, 0x15e0)),
                        mload(add(transcript, 0x15e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1620),
                    mulmod(
                        mload(add(transcript, 0x1600)),
                        mload(add(transcript, 0x1600)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1640),
                    mulmod(
                        mload(add(transcript, 0x1620)),
                        mload(add(transcript, 0x1620)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1660),
                    mulmod(
                        mload(add(transcript, 0x1640)),
                        mload(add(transcript, 0x1640)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1680),
                    mulmod(
                        mload(add(transcript, 0x1660)),
                        mload(add(transcript, 0x1660)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x16a0),
                    mulmod(
                        mload(add(transcript, 0x1680)),
                        mload(add(transcript, 0x1680)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x16c0),
                    mulmod(
                        mload(add(transcript, 0x16a0)),
                        mload(add(transcript, 0x16a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x16e0),
                    mulmod(
                        mload(add(transcript, 0x16c0)),
                        mload(add(transcript, 0x16c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1700),
                    mulmod(
                        mload(add(transcript, 0x16e0)),
                        mload(add(transcript, 0x16e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1720),
                    mulmod(
                        mload(add(transcript, 0x1700)),
                        mload(add(transcript, 0x1700)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1740),
                    mulmod(
                        mload(add(transcript, 0x1720)),
                        mload(add(transcript, 0x1720)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1760),
                    mulmod(
                        mload(add(transcript, 0x1740)),
                        mload(add(transcript, 0x1740)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1780),
                    mulmod(
                        mload(add(transcript, 0x1760)),
                        mload(add(transcript, 0x1760)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x17a0),
                    mulmod(
                        mload(add(transcript, 0x1780)),
                        mload(add(transcript, 0x1780)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x17c0),
                    mulmod(
                        mload(add(transcript, 0x17a0)),
                        mload(add(transcript, 0x17a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x17e0),
                    mulmod(
                        mload(add(transcript, 0x17c0)),
                        mload(add(transcript, 0x17c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1800),
                    addmod(
                        mload(add(transcript, 0x17e0)),
                        21888242871839275222246405745257275088548364400416034343698204186575808495616,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1820),
                    mulmod(
                        mload(add(transcript, 0x1800)),
                        21888075877798810139885396174900942254113179552665176677420557563313886988289,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1840),
                    mulmod(
                        mload(add(transcript, 0x1820)),
                        21180393220728113421338195116216869725258066600961496947533653125588029756005,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1860),
                    addmod(
                        mload(add(transcript, 0x920)),
                        707849651111161800908210629040405363290297799454537396164551060987778739612,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1880),
                    mulmod(
                        mload(add(transcript, 0x1820)),
                        18801136258871406524726641978934912926273987048785013233465874845411408769764,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x18a0),
                    addmod(
                        mload(add(transcript, 0x920)),
                        3087106612967868697519763766322362162274377351631021110232329341164399725853,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x18c0),
                    mulmod(
                        mload(add(transcript, 0x1820)),
                        13137266746974929847674828718073699700748973485900204084410541910719500618841,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x18e0),
                    addmod(
                        mload(add(transcript, 0x920)),
                        8750976124864345374571577027183575387799390914515830259287662275856307876776,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1900),
                    mulmod(
                        mload(add(transcript, 0x1820)),
                        14204982954615820785730815556166377574172276341958019443243371773666809943588,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1920),
                    addmod(
                        mload(add(transcript, 0x920)),
                        7683259917223454436515590189090897514376088058458014900454832412908998552029,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1940),
                    mulmod(
                        mload(add(transcript, 0x1820)),
                        9798514389911400568976296423560720718971335345616984532185711118739339214189,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1960),
                    addmod(
                        mload(add(transcript, 0x920)),
                        12089728481927874653270109321696554369577029054799049811512493067836469281428,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1980),
                    mulmod(
                        mload(add(transcript, 0x1820)),
                        5857228514216831962358810454360739186987616060007133076514874820078026801648,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x19a0),
                    addmod(
                        mload(add(transcript, 0x920)),
                        16031014357622443259887595290896535901560748340408901267183329366497781693969,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x19c0),
                    mulmod(
                        mload(add(transcript, 0x1820)),
                        11402394834529375719535454173347509224290498423785625657829583372803806900475,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x19e0),
                    addmod(
                        mload(add(transcript, 0x920)),
                        10485848037309899502710951571909765864257865976630408685868620813772001595142,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1a00),
                    mulmod(mload(add(transcript, 0x1820)), 1, f_q)
                )
                mstore(
                    add(transcript, 0x1a20),
                    addmod(
                        mload(add(transcript, 0x920)),
                        21888242871839275222246405745257275088548364400416034343698204186575808495616,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1a40),
                    mulmod(
                        mload(add(transcript, 0x1820)),
                        21846745818185811051373434299876022191132089169516983080959277716660228899818,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1a60),
                    addmod(
                        mload(add(transcript, 0x920)),
                        41497053653464170872971445381252897416275230899051262738926469915579595799,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1a80),
                    mulmod(
                        mload(add(transcript, 0x1820)),
                        4443263508319656594054352481848447997537391617204595126809744742387004492585,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1aa0),
                    addmod(
                        mload(add(transcript, 0x920)),
                        17444979363519618628192053263408827091010972783211439216888459444188804003032,
                        f_q
                    )
                )
                {
                    let prod := mload(add(transcript, 0x1860))
                    prod := mulmod(mload(add(transcript, 0x18a0)), prod, f_q)
                    mstore(add(transcript, 0x1ac0), prod)
                    prod := mulmod(mload(add(transcript, 0x18e0)), prod, f_q)
                    mstore(add(transcript, 0x1ae0), prod)
                    prod := mulmod(mload(add(transcript, 0x1920)), prod, f_q)
                    mstore(add(transcript, 0x1b00), prod)
                    prod := mulmod(mload(add(transcript, 0x1960)), prod, f_q)
                    mstore(add(transcript, 0x1b20), prod)
                    prod := mulmod(mload(add(transcript, 0x19a0)), prod, f_q)
                    mstore(add(transcript, 0x1b40), prod)
                    prod := mulmod(mload(add(transcript, 0x19e0)), prod, f_q)
                    mstore(add(transcript, 0x1b60), prod)
                    prod := mulmod(mload(add(transcript, 0x1a20)), prod, f_q)
                    mstore(add(transcript, 0x1b80), prod)
                    prod := mulmod(mload(add(transcript, 0x1a60)), prod, f_q)
                    mstore(add(transcript, 0x1ba0), prod)
                    prod := mulmod(mload(add(transcript, 0x1aa0)), prod, f_q)
                    mstore(add(transcript, 0x1bc0), prod)
                    prod := mulmod(mload(add(transcript, 0x1800)), prod, f_q)
                    mstore(add(transcript, 0x1be0), prod)
                }
                mstore(add(transcript, 0x1c20), 32)
                mstore(add(transcript, 0x1c40), 32)
                mstore(add(transcript, 0x1c60), 32)
                mstore(add(transcript, 0x1c80), mload(add(transcript, 0x1be0)))
                mstore(
                    add(transcript, 0x1ca0),
                    21888242871839275222246405745257275088548364400416034343698204186575808495615
                )
                mstore(
                    add(transcript, 0x1cc0),
                    21888242871839275222246405745257275088548364400416034343698204186575808495617
                )
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x5,
                            add(transcript, 0x1c20),
                            0xc0,
                            add(transcript, 0x1c00),
                            0x20
                        ),
                        1
                    ),
                    success
                )
                {
                    let inv := mload(add(transcript, 0x1c00))
                    let v
                    v := mload(add(transcript, 0x1800))
                    mstore(
                        add(transcript, 0x1800),
                        mulmod(mload(add(transcript, 0x1bc0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x1aa0))
                    mstore(
                        add(transcript, 0x1aa0),
                        mulmod(mload(add(transcript, 0x1ba0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x1a60))
                    mstore(
                        add(transcript, 0x1a60),
                        mulmod(mload(add(transcript, 0x1b80)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x1a20))
                    mstore(
                        add(transcript, 0x1a20),
                        mulmod(mload(add(transcript, 0x1b60)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x19e0))
                    mstore(
                        add(transcript, 0x19e0),
                        mulmod(mload(add(transcript, 0x1b40)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x19a0))
                    mstore(
                        add(transcript, 0x19a0),
                        mulmod(mload(add(transcript, 0x1b20)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x1960))
                    mstore(
                        add(transcript, 0x1960),
                        mulmod(mload(add(transcript, 0x1b00)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x1920))
                    mstore(
                        add(transcript, 0x1920),
                        mulmod(mload(add(transcript, 0x1ae0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x18e0))
                    mstore(
                        add(transcript, 0x18e0),
                        mulmod(mload(add(transcript, 0x1ac0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x18a0))
                    mstore(
                        add(transcript, 0x18a0),
                        mulmod(mload(add(transcript, 0x1860)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    mstore(add(transcript, 0x1860), inv)
                }
                mstore(
                    add(transcript, 0x1ce0),
                    mulmod(
                        mload(add(transcript, 0x1840)),
                        mload(add(transcript, 0x1860)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1d00),
                    mulmod(
                        mload(add(transcript, 0x1880)),
                        mload(add(transcript, 0x18a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1d20),
                    mulmod(
                        mload(add(transcript, 0x18c0)),
                        mload(add(transcript, 0x18e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1d40),
                    mulmod(
                        mload(add(transcript, 0x1900)),
                        mload(add(transcript, 0x1920)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1d60),
                    mulmod(
                        mload(add(transcript, 0x1940)),
                        mload(add(transcript, 0x1960)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1d80),
                    mulmod(
                        mload(add(transcript, 0x1980)),
                        mload(add(transcript, 0x19a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1da0),
                    mulmod(
                        mload(add(transcript, 0x19c0)),
                        mload(add(transcript, 0x19e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1dc0),
                    mulmod(
                        mload(add(transcript, 0x1a00)),
                        mload(add(transcript, 0x1a20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1de0),
                    mulmod(
                        mload(add(transcript, 0x1a40)),
                        mload(add(transcript, 0x1a60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1e00),
                    mulmod(
                        mload(add(transcript, 0x1a80)),
                        mload(add(transcript, 0x1aa0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1dc0)),
                        mload(add(transcript, 0x20)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1de0)),
                            mload(add(transcript, 0x40)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1e00)),
                            mload(add(transcript, 0x60)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x1e20), result)
                }
                mstore(
                    add(transcript, 0x1e40),
                    addmod(2, sub(f_q, mload(add(transcript, 0xe40))), f_q)
                )
                mstore(
                    add(transcript, 0x1e60),
                    mulmod(
                        mload(add(transcript, 0x1e40)),
                        mload(add(transcript, 0xe40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1e80),
                    mulmod(
                        mload(add(transcript, 0x9a0)),
                        mload(add(transcript, 0x980)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1ea0),
                    addmod(
                        mload(add(transcript, 0x960)),
                        mload(add(transcript, 0x1e80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1ec0),
                    addmod(
                        mload(add(transcript, 0x1ea0)),
                        sub(f_q, mload(add(transcript, 0x9c0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1ee0),
                    mulmod(
                        mload(add(transcript, 0x1ec0)),
                        mload(add(transcript, 0x1e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1f00),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x1ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1f20),
                    addmod(2, sub(f_q, mload(add(transcript, 0xe60))), f_q)
                )
                mstore(
                    add(transcript, 0x1f40),
                    mulmod(
                        mload(add(transcript, 0x1f20)),
                        mload(add(transcript, 0xe60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1f60),
                    mulmod(
                        mload(add(transcript, 0xa20)),
                        mload(add(transcript, 0xa00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1f80),
                    addmod(
                        mload(add(transcript, 0x9e0)),
                        mload(add(transcript, 0x1f60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1fa0),
                    addmod(
                        mload(add(transcript, 0x1f80)),
                        sub(f_q, mload(add(transcript, 0xa40))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1fc0),
                    mulmod(
                        mload(add(transcript, 0x1fa0)),
                        mload(add(transcript, 0x1f40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x1fe0),
                    addmod(
                        mload(add(transcript, 0x1f00)),
                        mload(add(transcript, 0x1fc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2000),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x1fe0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2020),
                    addmod(2, sub(f_q, mload(add(transcript, 0xe80))), f_q)
                )
                mstore(
                    add(transcript, 0x2040),
                    mulmod(
                        mload(add(transcript, 0x2020)),
                        mload(add(transcript, 0xe80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2060),
                    mulmod(
                        mload(add(transcript, 0xaa0)),
                        mload(add(transcript, 0xa80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2080),
                    addmod(
                        mload(add(transcript, 0xa60)),
                        mload(add(transcript, 0x2060)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x20a0),
                    addmod(
                        mload(add(transcript, 0x2080)),
                        sub(f_q, mload(add(transcript, 0xac0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x20c0),
                    mulmod(
                        mload(add(transcript, 0x20a0)),
                        mload(add(transcript, 0x2040)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x20e0),
                    addmod(
                        mload(add(transcript, 0x2000)),
                        mload(add(transcript, 0x20c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2100),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x20e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2120),
                    addmod(2, sub(f_q, mload(add(transcript, 0xea0))), f_q)
                )
                mstore(
                    add(transcript, 0x2140),
                    mulmod(
                        mload(add(transcript, 0x2120)),
                        mload(add(transcript, 0xea0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2160),
                    mulmod(
                        mload(add(transcript, 0xb20)),
                        mload(add(transcript, 0xb00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2180),
                    addmod(
                        mload(add(transcript, 0xae0)),
                        mload(add(transcript, 0x2160)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x21a0),
                    addmod(
                        mload(add(transcript, 0x2180)),
                        sub(f_q, mload(add(transcript, 0xb40))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x21c0),
                    mulmod(
                        mload(add(transcript, 0x21a0)),
                        mload(add(transcript, 0x2140)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x21e0),
                    addmod(
                        mload(add(transcript, 0x2100)),
                        mload(add(transcript, 0x21c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2200),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x21e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2220),
                    addmod(1, sub(f_q, mload(add(transcript, 0xe40))), f_q)
                )
                mstore(
                    add(transcript, 0x2240),
                    mulmod(
                        mload(add(transcript, 0x2220)),
                        mload(add(transcript, 0xe40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2260),
                    mulmod(
                        mload(add(transcript, 0xba0)),
                        mload(add(transcript, 0xb80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2280),
                    addmod(
                        mload(add(transcript, 0xb60)),
                        mload(add(transcript, 0x2260)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x22a0),
                    addmod(
                        mload(add(transcript, 0x2280)),
                        sub(f_q, mload(add(transcript, 0xbc0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x22c0),
                    mulmod(
                        mload(add(transcript, 0x22a0)),
                        mload(add(transcript, 0x2240)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x22e0),
                    addmod(
                        mload(add(transcript, 0x2200)),
                        mload(add(transcript, 0x22c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2300),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x22e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2320),
                    addmod(1, sub(f_q, mload(add(transcript, 0xe60))), f_q)
                )
                mstore(
                    add(transcript, 0x2340),
                    mulmod(
                        mload(add(transcript, 0x2320)),
                        mload(add(transcript, 0xe60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2360),
                    mulmod(
                        mload(add(transcript, 0xc20)),
                        mload(add(transcript, 0xc00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2380),
                    addmod(
                        mload(add(transcript, 0xbe0)),
                        mload(add(transcript, 0x2360)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x23a0),
                    addmod(
                        mload(add(transcript, 0x2380)),
                        sub(f_q, mload(add(transcript, 0xc40))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x23c0),
                    mulmod(
                        mload(add(transcript, 0x23a0)),
                        mload(add(transcript, 0x2340)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x23e0),
                    addmod(
                        mload(add(transcript, 0x2300)),
                        mload(add(transcript, 0x23c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2400),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x23e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2420),
                    addmod(1, sub(f_q, mload(add(transcript, 0xe80))), f_q)
                )
                mstore(
                    add(transcript, 0x2440),
                    mulmod(
                        mload(add(transcript, 0x2420)),
                        mload(add(transcript, 0xe80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2460),
                    mulmod(
                        mload(add(transcript, 0xca0)),
                        mload(add(transcript, 0xc80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2480),
                    addmod(
                        mload(add(transcript, 0xc60)),
                        mload(add(transcript, 0x2460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x24a0),
                    addmod(
                        mload(add(transcript, 0x2480)),
                        sub(f_q, mload(add(transcript, 0xcc0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x24c0),
                    mulmod(
                        mload(add(transcript, 0x24a0)),
                        mload(add(transcript, 0x2440)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x24e0),
                    addmod(
                        mload(add(transcript, 0x2400)),
                        mload(add(transcript, 0x24c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2500),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x24e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2520),
                    addmod(1, sub(f_q, mload(add(transcript, 0xea0))), f_q)
                )
                mstore(
                    add(transcript, 0x2540),
                    mulmod(
                        mload(add(transcript, 0x2520)),
                        mload(add(transcript, 0xea0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2560),
                    mulmod(
                        mload(add(transcript, 0xd20)),
                        mload(add(transcript, 0xd00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2580),
                    addmod(
                        mload(add(transcript, 0xce0)),
                        mload(add(transcript, 0x2560)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x25a0),
                    addmod(
                        mload(add(transcript, 0x2580)),
                        sub(f_q, mload(add(transcript, 0xd40))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x25c0),
                    mulmod(
                        mload(add(transcript, 0x25a0)),
                        mload(add(transcript, 0x2540)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x25e0),
                    addmod(
                        mload(add(transcript, 0x2500)),
                        mload(add(transcript, 0x25c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2600),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x25e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2620),
                    addmod(1, sub(f_q, mload(add(transcript, 0x1080))), f_q)
                )
                mstore(
                    add(transcript, 0x2640),
                    mulmod(
                        mload(add(transcript, 0x2620)),
                        mload(add(transcript, 0x1dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2660),
                    addmod(
                        mload(add(transcript, 0x2600)),
                        mload(add(transcript, 0x2640)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2680),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x2660)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x26a0),
                    mulmod(
                        mload(add(transcript, 0x12c0)),
                        mload(add(transcript, 0x12c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x26c0),
                    addmod(
                        mload(add(transcript, 0x26a0)),
                        sub(f_q, mload(add(transcript, 0x12c0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x26e0),
                    mulmod(
                        mload(add(transcript, 0x26c0)),
                        mload(add(transcript, 0x1ce0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2700),
                    addmod(
                        mload(add(transcript, 0x2680)),
                        mload(add(transcript, 0x26e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2720),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x2700)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2740),
                    addmod(
                        mload(add(transcript, 0x10e0)),
                        sub(f_q, mload(add(transcript, 0x10c0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2760),
                    mulmod(
                        mload(add(transcript, 0x2740)),
                        mload(add(transcript, 0x1dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2780),
                    addmod(
                        mload(add(transcript, 0x2720)),
                        mload(add(transcript, 0x2760)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x27a0),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x2780)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x27c0),
                    addmod(
                        mload(add(transcript, 0x1140)),
                        sub(f_q, mload(add(transcript, 0x1120))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x27e0),
                    mulmod(
                        mload(add(transcript, 0x27c0)),
                        mload(add(transcript, 0x1dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2800),
                    addmod(
                        mload(add(transcript, 0x27a0)),
                        mload(add(transcript, 0x27e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2820),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x2800)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2840),
                    addmod(
                        mload(add(transcript, 0x11a0)),
                        sub(f_q, mload(add(transcript, 0x1180))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2860),
                    mulmod(
                        mload(add(transcript, 0x2840)),
                        mload(add(transcript, 0x1dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2880),
                    addmod(
                        mload(add(transcript, 0x2820)),
                        mload(add(transcript, 0x2860)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x28a0),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x2880)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x28c0),
                    addmod(
                        mload(add(transcript, 0x1200)),
                        sub(f_q, mload(add(transcript, 0x11e0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x28e0),
                    mulmod(
                        mload(add(transcript, 0x28c0)),
                        mload(add(transcript, 0x1dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2900),
                    addmod(
                        mload(add(transcript, 0x28a0)),
                        mload(add(transcript, 0x28e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2920),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x2900)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2940),
                    addmod(
                        mload(add(transcript, 0x1260)),
                        sub(f_q, mload(add(transcript, 0x1240))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2960),
                    mulmod(
                        mload(add(transcript, 0x2940)),
                        mload(add(transcript, 0x1dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2980),
                    addmod(
                        mload(add(transcript, 0x2920)),
                        mload(add(transcript, 0x2960)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x29a0),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x2980)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x29c0),
                    addmod(
                        mload(add(transcript, 0x12c0)),
                        sub(f_q, mload(add(transcript, 0x12a0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x29e0),
                    mulmod(
                        mload(add(transcript, 0x29c0)),
                        mload(add(transcript, 0x1dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2a00),
                    addmod(
                        mload(add(transcript, 0x29a0)),
                        mload(add(transcript, 0x29e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2a20),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x2a00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2a40),
                    addmod(1, sub(f_q, mload(add(transcript, 0x1ce0))), f_q)
                )
                mstore(
                    add(transcript, 0x2a60),
                    addmod(
                        mload(add(transcript, 0x1d00)),
                        mload(add(transcript, 0x1d20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2a80),
                    addmod(
                        mload(add(transcript, 0x2a60)),
                        mload(add(transcript, 0x1d40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2aa0),
                    addmod(
                        mload(add(transcript, 0x2a80)),
                        mload(add(transcript, 0x1d60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2ac0),
                    addmod(
                        mload(add(transcript, 0x2aa0)),
                        mload(add(transcript, 0x1d80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2ae0),
                    addmod(
                        mload(add(transcript, 0x2ac0)),
                        mload(add(transcript, 0x1da0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2b00),
                    addmod(
                        mload(add(transcript, 0x2a40)),
                        sub(f_q, mload(add(transcript, 0x2ae0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2b20),
                    mulmod(
                        mload(add(transcript, 0xee0)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2b40),
                    addmod(
                        mload(add(transcript, 0xdc0)),
                        mload(add(transcript, 0x2b20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2b60),
                    addmod(
                        mload(add(transcript, 0x2b40)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2b80),
                    mulmod(
                        mload(add(transcript, 0xf00)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2ba0),
                    addmod(
                        mload(add(transcript, 0x960)),
                        mload(add(transcript, 0x2b80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2bc0),
                    addmod(
                        mload(add(transcript, 0x2ba0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2be0),
                    mulmod(
                        mload(add(transcript, 0x2bc0)),
                        mload(add(transcript, 0x2b60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2c00),
                    mulmod(
                        mload(add(transcript, 0x2be0)),
                        mload(add(transcript, 0x10a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2c20),
                    mulmod(1, mload(add(transcript, 0x4c0)), f_q)
                )
                mstore(
                    add(transcript, 0x2c40),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x2c20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2c60),
                    addmod(
                        mload(add(transcript, 0xdc0)),
                        mload(add(transcript, 0x2c40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2c80),
                    addmod(
                        mload(add(transcript, 0x2c60)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2ca0),
                    mulmod(
                        4131629893567559867359510883348571134090853742863529169391034518566172092834,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2cc0),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x2ca0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2ce0),
                    addmod(
                        mload(add(transcript, 0x960)),
                        mload(add(transcript, 0x2cc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2d00),
                    addmod(
                        mload(add(transcript, 0x2ce0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2d20),
                    mulmod(
                        mload(add(transcript, 0x2d00)),
                        mload(add(transcript, 0x2c80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2d40),
                    mulmod(
                        mload(add(transcript, 0x2d20)),
                        mload(add(transcript, 0x1080)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2d60),
                    addmod(
                        mload(add(transcript, 0x2c00)),
                        sub(f_q, mload(add(transcript, 0x2d40))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2d80),
                    mulmod(
                        mload(add(transcript, 0x2d60)),
                        mload(add(transcript, 0x2b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2da0),
                    addmod(
                        mload(add(transcript, 0x2a20)),
                        mload(add(transcript, 0x2d80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2dc0),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x2da0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2de0),
                    mulmod(
                        mload(add(transcript, 0xf20)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2e00),
                    addmod(
                        mload(add(transcript, 0x9e0)),
                        mload(add(transcript, 0x2de0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2e20),
                    addmod(
                        mload(add(transcript, 0x2e00)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2e40),
                    mulmod(
                        mload(add(transcript, 0xf40)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2e60),
                    addmod(
                        mload(add(transcript, 0xa60)),
                        mload(add(transcript, 0x2e40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2e80),
                    addmod(
                        mload(add(transcript, 0x2e60)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2ea0),
                    mulmod(
                        mload(add(transcript, 0x2e80)),
                        mload(add(transcript, 0x2e20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2ec0),
                    mulmod(
                        mload(add(transcript, 0x2ea0)),
                        mload(add(transcript, 0x1100)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2ee0),
                    mulmod(
                        8910878055287538404433155982483128285667088683464058436815641868457422632747,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2f00),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x2ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2f20),
                    addmod(
                        mload(add(transcript, 0x9e0)),
                        mload(add(transcript, 0x2f00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2f40),
                    addmod(
                        mload(add(transcript, 0x2f20)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2f60),
                    mulmod(
                        11166246659983828508719468090013646171463329086121580628794302409516816350802,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2f80),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x2f60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2fa0),
                    addmod(
                        mload(add(transcript, 0xa60)),
                        mload(add(transcript, 0x2f80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2fc0),
                    addmod(
                        mload(add(transcript, 0x2fa0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x2fe0),
                    mulmod(
                        mload(add(transcript, 0x2fc0)),
                        mload(add(transcript, 0x2f40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3000),
                    mulmod(
                        mload(add(transcript, 0x2fe0)),
                        mload(add(transcript, 0x10e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3020),
                    addmod(
                        mload(add(transcript, 0x2ec0)),
                        sub(f_q, mload(add(transcript, 0x3000))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3040),
                    mulmod(
                        mload(add(transcript, 0x3020)),
                        mload(add(transcript, 0x2b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3060),
                    addmod(
                        mload(add(transcript, 0x2dc0)),
                        mload(add(transcript, 0x3040)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3080),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x3060)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x30a0),
                    mulmod(
                        mload(add(transcript, 0xf60)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x30c0),
                    addmod(
                        mload(add(transcript, 0xae0)),
                        mload(add(transcript, 0x30a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x30e0),
                    addmod(
                        mload(add(transcript, 0x30c0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3100),
                    mulmod(
                        mload(add(transcript, 0xf80)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3120),
                    addmod(
                        mload(add(transcript, 0xb60)),
                        mload(add(transcript, 0x3100)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3140),
                    addmod(
                        mload(add(transcript, 0x3120)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3160),
                    mulmod(
                        mload(add(transcript, 0x3140)),
                        mload(add(transcript, 0x30e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3180),
                    mulmod(
                        mload(add(transcript, 0x3160)),
                        mload(add(transcript, 0x1160)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x31a0),
                    mulmod(
                        284840088355319032285349970403338060113257071685626700086398481893096618818,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x31c0),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x31a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x31e0),
                    addmod(
                        mload(add(transcript, 0xae0)),
                        mload(add(transcript, 0x31c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3200),
                    addmod(
                        mload(add(transcript, 0x31e0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3220),
                    mulmod(
                        21134065618345176623193549882539580312263652408302468683943992798037078993309,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3240),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x3220)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3260),
                    addmod(
                        mload(add(transcript, 0xb60)),
                        mload(add(transcript, 0x3240)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3280),
                    addmod(
                        mload(add(transcript, 0x3260)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x32a0),
                    mulmod(
                        mload(add(transcript, 0x3280)),
                        mload(add(transcript, 0x3200)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x32c0),
                    mulmod(
                        mload(add(transcript, 0x32a0)),
                        mload(add(transcript, 0x1140)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x32e0),
                    addmod(
                        mload(add(transcript, 0x3180)),
                        sub(f_q, mload(add(transcript, 0x32c0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3300),
                    mulmod(
                        mload(add(transcript, 0x32e0)),
                        mload(add(transcript, 0x2b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3320),
                    addmod(
                        mload(add(transcript, 0x3080)),
                        mload(add(transcript, 0x3300)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3340),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x3320)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3360),
                    mulmod(
                        mload(add(transcript, 0xfa0)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3380),
                    addmod(
                        mload(add(transcript, 0xbe0)),
                        mload(add(transcript, 0x3360)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x33a0),
                    addmod(
                        mload(add(transcript, 0x3380)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x33c0),
                    mulmod(
                        mload(add(transcript, 0xfc0)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x33e0),
                    addmod(
                        mload(add(transcript, 0xc60)),
                        mload(add(transcript, 0x33c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3400),
                    addmod(
                        mload(add(transcript, 0x33e0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3420),
                    mulmod(
                        mload(add(transcript, 0x3400)),
                        mload(add(transcript, 0x33a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3440),
                    mulmod(
                        mload(add(transcript, 0x3420)),
                        mload(add(transcript, 0x11c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3460),
                    mulmod(
                        5625741653535312224677218588085279924365897425605943700675464992185016992283,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3480),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x3460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x34a0),
                    addmod(
                        mload(add(transcript, 0xbe0)),
                        mload(add(transcript, 0x3480)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x34c0),
                    addmod(
                        mload(add(transcript, 0x34a0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x34e0),
                    mulmod(
                        14704729814417906439424896605881467874595262020190401576785074330126828718155,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3500),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x34e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3520),
                    addmod(
                        mload(add(transcript, 0xc60)),
                        mload(add(transcript, 0x3500)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3540),
                    addmod(
                        mload(add(transcript, 0x3520)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3560),
                    mulmod(
                        mload(add(transcript, 0x3540)),
                        mload(add(transcript, 0x34c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3580),
                    mulmod(
                        mload(add(transcript, 0x3560)),
                        mload(add(transcript, 0x11a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x35a0),
                    addmod(
                        mload(add(transcript, 0x3440)),
                        sub(f_q, mload(add(transcript, 0x3580))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x35c0),
                    mulmod(
                        mload(add(transcript, 0x35a0)),
                        mload(add(transcript, 0x2b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x35e0),
                    addmod(
                        mload(add(transcript, 0x3340)),
                        mload(add(transcript, 0x35c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3600),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x35e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3620),
                    mulmod(
                        mload(add(transcript, 0xfe0)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3640),
                    addmod(
                        mload(add(transcript, 0xce0)),
                        mload(add(transcript, 0x3620)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3660),
                    addmod(
                        mload(add(transcript, 0x3640)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3680),
                    mulmod(
                        mload(add(transcript, 0x1000)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x36a0),
                    addmod(
                        mload(add(transcript, 0xd60)),
                        mload(add(transcript, 0x3680)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x36c0),
                    addmod(
                        mload(add(transcript, 0x36a0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x36e0),
                    mulmod(
                        mload(add(transcript, 0x36c0)),
                        mload(add(transcript, 0x3660)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3700),
                    mulmod(
                        mload(add(transcript, 0x36e0)),
                        mload(add(transcript, 0x1220)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3720),
                    mulmod(
                        8343274462013750416000956870576256937330525306073862550863787263304548803879,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3740),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x3720)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3760),
                    addmod(
                        mload(add(transcript, 0xce0)),
                        mload(add(transcript, 0x3740)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3780),
                    addmod(
                        mload(add(transcript, 0x3760)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x37a0),
                    mulmod(
                        20928372310071051017340352686640453451620397549739756658327314209761852842004,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x37c0),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x37a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x37e0),
                    addmod(
                        mload(add(transcript, 0xd60)),
                        mload(add(transcript, 0x37c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3800),
                    addmod(
                        mload(add(transcript, 0x37e0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3820),
                    mulmod(
                        mload(add(transcript, 0x3800)),
                        mload(add(transcript, 0x3780)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3840),
                    mulmod(
                        mload(add(transcript, 0x3820)),
                        mload(add(transcript, 0x1200)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3860),
                    addmod(
                        mload(add(transcript, 0x3700)),
                        sub(f_q, mload(add(transcript, 0x3840))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3880),
                    mulmod(
                        mload(add(transcript, 0x3860)),
                        mload(add(transcript, 0x2b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x38a0),
                    addmod(
                        mload(add(transcript, 0x3600)),
                        mload(add(transcript, 0x3880)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x38c0),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x38a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x38e0),
                    mulmod(
                        mload(add(transcript, 0x1020)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3900),
                    addmod(
                        mload(add(transcript, 0xd80)),
                        mload(add(transcript, 0x38e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3920),
                    addmod(
                        mload(add(transcript, 0x3900)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3940),
                    mulmod(
                        mload(add(transcript, 0x1040)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3960),
                    addmod(
                        mload(add(transcript, 0xda0)),
                        mload(add(transcript, 0x3940)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3980),
                    addmod(
                        mload(add(transcript, 0x3960)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x39a0),
                    mulmod(
                        mload(add(transcript, 0x3980)),
                        mload(add(transcript, 0x3920)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x39c0),
                    mulmod(
                        mload(add(transcript, 0x39a0)),
                        mload(add(transcript, 0x1280)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x39e0),
                    mulmod(
                        15845651941796975697993789271154426079663327509658641548785793587449119139335,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3a00),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x39e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3a20),
                    addmod(
                        mload(add(transcript, 0xd80)),
                        mload(add(transcript, 0x3a00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3a40),
                    addmod(
                        mload(add(transcript, 0x3a20)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3a60),
                    mulmod(
                        8045145839887181143520022567602912517500076612542816225981084745629998235872,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3a80),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x3a60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3aa0),
                    addmod(
                        mload(add(transcript, 0xda0)),
                        mload(add(transcript, 0x3a80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3ac0),
                    addmod(
                        mload(add(transcript, 0x3aa0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3ae0),
                    mulmod(
                        mload(add(transcript, 0x3ac0)),
                        mload(add(transcript, 0x3a40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3b00),
                    mulmod(
                        mload(add(transcript, 0x3ae0)),
                        mload(add(transcript, 0x1260)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3b20),
                    addmod(
                        mload(add(transcript, 0x39c0)),
                        sub(f_q, mload(add(transcript, 0x3b00))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3b40),
                    mulmod(
                        mload(add(transcript, 0x3b20)),
                        mload(add(transcript, 0x2b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3b60),
                    addmod(
                        mload(add(transcript, 0x38c0)),
                        mload(add(transcript, 0x3b40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3b80),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x3b60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3ba0),
                    mulmod(
                        mload(add(transcript, 0x1060)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3bc0),
                    addmod(
                        mload(add(transcript, 0x1e20)),
                        mload(add(transcript, 0x3ba0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3be0),
                    addmod(
                        mload(add(transcript, 0x3bc0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3c00),
                    mulmod(
                        mload(add(transcript, 0x3be0)),
                        mload(add(transcript, 0x12e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3c20),
                    mulmod(
                        2381670505483685611182091218417223919364072893694444758025506701602682587318,
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3c40),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        mload(add(transcript, 0x3c20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3c60),
                    addmod(
                        mload(add(transcript, 0x1e20)),
                        mload(add(transcript, 0x3c40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3c80),
                    addmod(
                        mload(add(transcript, 0x3c60)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3ca0),
                    mulmod(
                        mload(add(transcript, 0x3c80)),
                        mload(add(transcript, 0x12c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3cc0),
                    addmod(
                        mload(add(transcript, 0x3c00)),
                        sub(f_q, mload(add(transcript, 0x3ca0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3ce0),
                    mulmod(
                        mload(add(transcript, 0x3cc0)),
                        mload(add(transcript, 0x2b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3d00),
                    addmod(
                        mload(add(transcript, 0x3b80)),
                        mload(add(transcript, 0x3ce0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3d20),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x3d00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3d40),
                    addmod(1, sub(f_q, mload(add(transcript, 0x1300))), f_q)
                )
                mstore(
                    add(transcript, 0x3d60),
                    mulmod(
                        mload(add(transcript, 0x3d40)),
                        mload(add(transcript, 0x1dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3d80),
                    addmod(
                        mload(add(transcript, 0x3d20)),
                        mload(add(transcript, 0x3d60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3da0),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x3d80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3dc0),
                    mulmod(
                        mload(add(transcript, 0x1300)),
                        mload(add(transcript, 0x1300)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3de0),
                    addmod(
                        mload(add(transcript, 0x3dc0)),
                        sub(f_q, mload(add(transcript, 0x1300))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3e00),
                    mulmod(
                        mload(add(transcript, 0x3de0)),
                        mload(add(transcript, 0x1ce0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3e20),
                    addmod(
                        mload(add(transcript, 0x3da0)),
                        mload(add(transcript, 0x3e00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3e40),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x3e20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3e60),
                    addmod(
                        mload(add(transcript, 0x1340)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3e80),
                    mulmod(
                        mload(add(transcript, 0x3e60)),
                        mload(add(transcript, 0x1320)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3ea0),
                    addmod(
                        mload(add(transcript, 0x1380)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3ec0),
                    mulmod(
                        mload(add(transcript, 0x3ea0)),
                        mload(add(transcript, 0x3e80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3ee0),
                    addmod(
                        mload(add(transcript, 0xd60)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3f00),
                    mulmod(
                        mload(add(transcript, 0x3ee0)),
                        mload(add(transcript, 0x1300)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3f20),
                    addmod(
                        mload(add(transcript, 0xde0)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3f40),
                    mulmod(
                        mload(add(transcript, 0x3f20)),
                        mload(add(transcript, 0x3f00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3f60),
                    addmod(
                        mload(add(transcript, 0x3ec0)),
                        sub(f_q, mload(add(transcript, 0x3f40))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3f80),
                    mulmod(
                        mload(add(transcript, 0x3f60)),
                        mload(add(transcript, 0x2b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3fa0),
                    addmod(
                        mload(add(transcript, 0x3e40)),
                        mload(add(transcript, 0x3f80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3fc0),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x3fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x3fe0),
                    addmod(
                        mload(add(transcript, 0x1340)),
                        sub(f_q, mload(add(transcript, 0x1380))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4000),
                    mulmod(
                        mload(add(transcript, 0x3fe0)),
                        mload(add(transcript, 0x1dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4020),
                    addmod(
                        mload(add(transcript, 0x3fc0)),
                        mload(add(transcript, 0x4000)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4040),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x4020)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4060),
                    mulmod(
                        mload(add(transcript, 0x3fe0)),
                        mload(add(transcript, 0x2b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4080),
                    addmod(
                        mload(add(transcript, 0x1340)),
                        sub(f_q, mload(add(transcript, 0x1360))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x40a0),
                    mulmod(
                        mload(add(transcript, 0x4080)),
                        mload(add(transcript, 0x4060)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x40c0),
                    addmod(
                        mload(add(transcript, 0x4040)),
                        mload(add(transcript, 0x40a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x40e0),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x40c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4100),
                    addmod(1, sub(f_q, mload(add(transcript, 0x13a0))), f_q)
                )
                mstore(
                    add(transcript, 0x4120),
                    mulmod(
                        mload(add(transcript, 0x4100)),
                        mload(add(transcript, 0x1dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4140),
                    addmod(
                        mload(add(transcript, 0x40e0)),
                        mload(add(transcript, 0x4120)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4160),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x4140)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4180),
                    mulmod(
                        mload(add(transcript, 0x13a0)),
                        mload(add(transcript, 0x13a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x41a0),
                    addmod(
                        mload(add(transcript, 0x4180)),
                        sub(f_q, mload(add(transcript, 0x13a0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x41c0),
                    mulmod(
                        mload(add(transcript, 0x41a0)),
                        mload(add(transcript, 0x1ce0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x41e0),
                    addmod(
                        mload(add(transcript, 0x4160)),
                        mload(add(transcript, 0x41c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4200),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x41e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4220),
                    addmod(
                        mload(add(transcript, 0x13e0)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4240),
                    mulmod(
                        mload(add(transcript, 0x4220)),
                        mload(add(transcript, 0x13c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4260),
                    addmod(
                        mload(add(transcript, 0x1420)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4280),
                    mulmod(
                        mload(add(transcript, 0x4260)),
                        mload(add(transcript, 0x4240)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x42a0),
                    mulmod(
                        mload(add(transcript, 0x360)),
                        mload(add(transcript, 0xd80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x42c0),
                    addmod(
                        mload(add(transcript, 0x42a0)),
                        mload(add(transcript, 0xda0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x42e0),
                    addmod(
                        mload(add(transcript, 0x42c0)),
                        mload(add(transcript, 0x4c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4300),
                    mulmod(
                        mload(add(transcript, 0x42e0)),
                        mload(add(transcript, 0x13a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4320),
                    mulmod(
                        mload(add(transcript, 0x360)),
                        mload(add(transcript, 0xe00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4340),
                    addmod(
                        mload(add(transcript, 0x4320)),
                        mload(add(transcript, 0xe20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4360),
                    addmod(
                        mload(add(transcript, 0x4340)),
                        mload(add(transcript, 0x520)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4380),
                    mulmod(
                        mload(add(transcript, 0x4360)),
                        mload(add(transcript, 0x4300)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x43a0),
                    addmod(
                        mload(add(transcript, 0x4280)),
                        sub(f_q, mload(add(transcript, 0x4380))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x43c0),
                    mulmod(
                        mload(add(transcript, 0x43a0)),
                        mload(add(transcript, 0x2b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x43e0),
                    addmod(
                        mload(add(transcript, 0x4200)),
                        mload(add(transcript, 0x43c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4400),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x43e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4420),
                    addmod(
                        mload(add(transcript, 0x13e0)),
                        sub(f_q, mload(add(transcript, 0x1420))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4440),
                    mulmod(
                        mload(add(transcript, 0x4420)),
                        mload(add(transcript, 0x1dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4460),
                    addmod(
                        mload(add(transcript, 0x4400)),
                        mload(add(transcript, 0x4440)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4480),
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x4460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x44a0),
                    mulmod(
                        mload(add(transcript, 0x4420)),
                        mload(add(transcript, 0x2b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x44c0),
                    addmod(
                        mload(add(transcript, 0x13e0)),
                        sub(f_q, mload(add(transcript, 0x1400))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x44e0),
                    mulmod(
                        mload(add(transcript, 0x44c0)),
                        mload(add(transcript, 0x44a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4500),
                    addmod(
                        mload(add(transcript, 0x4480)),
                        mload(add(transcript, 0x44e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4520),
                    mulmod(
                        mload(add(transcript, 0x17e0)),
                        mload(add(transcript, 0x17e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4540),
                    mulmod(
                        mload(add(transcript, 0x4520)),
                        mload(add(transcript, 0x17e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4560),
                    mulmod(1, mload(add(transcript, 0x17e0)), f_q)
                )
                mstore(
                    add(transcript, 0x4580),
                    mulmod(1, mload(add(transcript, 0x4520)), f_q)
                )
                mstore(
                    add(transcript, 0x45a0),
                    mulmod(
                        mload(add(transcript, 0x4500)),
                        mload(add(transcript, 0x1800)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x45c0),
                    mulmod(
                        mload(add(transcript, 0x15e0)),
                        mload(add(transcript, 0x920)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x45e0),
                    mulmod(mload(add(transcript, 0x920)), 1, f_q)
                )
                mstore(
                    add(transcript, 0x4600),
                    addmod(
                        mload(add(transcript, 0x1560)),
                        sub(f_q, mload(add(transcript, 0x45e0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4620),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        4443263508319656594054352481848447997537391617204595126809744742387004492585,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4640),
                    addmod(
                        mload(add(transcript, 0x1560)),
                        sub(f_q, mload(add(transcript, 0x4620))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4660),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        11402394834529375719535454173347509224290498423785625657829583372803806900475,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4680),
                    addmod(
                        mload(add(transcript, 0x1560)),
                        sub(f_q, mload(add(transcript, 0x4660))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x46a0),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        12491230264321380165669116208790466830459716800431293091713220204712467607643,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x46c0),
                    addmod(
                        mload(add(transcript, 0x1560)),
                        sub(f_q, mload(add(transcript, 0x46a0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x46e0),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        21180393220728113421338195116216869725258066600961496947533653125588029756005,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4700),
                    addmod(
                        mload(add(transcript, 0x1560)),
                        sub(f_q, mload(add(transcript, 0x46e0))),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4720),
                    mulmod(
                        mload(add(transcript, 0x920)),
                        21846745818185811051373434299876022191132089169516983080959277716660228899818,
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4740),
                    addmod(
                        mload(add(transcript, 0x1560)),
                        sub(f_q, mload(add(transcript, 0x4720))),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1560)),
                        8066282055787475901673420555035560535710817593291328670948830103998216087188,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            13821960816051799320572985190221714552837546807124705672749374082577592408429,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4760), result)
                }
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1560)),
                        19968324678227145013248315861515595301245912644541587902686803196084490696647,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            2652279421035414460371318391121293595959370598409287323185787737283079651270,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4780), result)
                }
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1560)),
                        2652279421035414460371318391121293595959370598409287323185787737283079651270,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            19367074469347227157046979956364450920724362242668588573146737185273452907601,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x47a0), result)
                }
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1560)),
                        5728955065969648051880489897163235636379640954457863903141118671545973649876,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            11131803335553698406238999414095177806538558655198059953539642575164592088996,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x47c0), result)
                }
                mstore(
                    add(transcript, 0x47e0),
                    mulmod(1, mload(add(transcript, 0x4600)), f_q)
                )
                mstore(
                    add(transcript, 0x4800),
                    mulmod(
                        mload(add(transcript, 0x47e0)),
                        mload(add(transcript, 0x4740)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4820),
                    mulmod(
                        mload(add(transcript, 0x4800)),
                        mload(add(transcript, 0x4640)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4840),
                    mulmod(
                        mload(add(transcript, 0x4820)),
                        mload(add(transcript, 0x46c0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(mload(add(transcript, 0x1560)), 1, f_q)
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            21888242871839275222246405745257275088548364400416034343698204186575808495616,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4860), result)
                }
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1560)),
                        19550482963636032496507824053356571186980560079138601892369352376314767105176,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            2337759908203242725738581691900703901567804321277432451328851810261041390441,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4880), result)
                }
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1560)),
                        6864017523829827661538877064511657693937746400280130103616449492479205074625,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            8176406603941074973579828757454043030101025654304527229739395789558437229636,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x48a0), result)
                }
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1560)),
                        1208363231502528720962640213919841679473696796176395546734070070553011066292,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            13927816816077446377946003702584403455282257763096126200719395408961442331222,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x48c0), result)
                }
                mstore(
                    add(transcript, 0x48e0),
                    mulmod(
                        mload(add(transcript, 0x4800)),
                        mload(add(transcript, 0x4700)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1560)),
                        41497053653464170872971445381252897416275230899051262738926469915579595800,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            21846745818185811051373434299876022191132089169516983080959277716660228899817,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4900), result)
                }
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1560)),
                        21846745818185811051373434299876022191132089169516983080959277716660228899817,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            17403482309866154457319081818027574193594697552312387954149532974273224407233,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4920), result)
                }
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1560)),
                        10485848037309899502710951571909765864257865976630408685868620813772001595143,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            11402394834529375719535454173347509224290498423785625657829583372803806900474,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4940), result)
                }
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1560)),
                        11402394834529375719535454173347509224290498423785625657829583372803806900474,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x920)),
                            5545166320312543757176643718986770037302882363778492581314708552725780098827,
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4960), result)
                }
                mstore(
                    add(transcript, 0x4980),
                    mulmod(
                        mload(add(transcript, 0x47e0)),
                        mload(add(transcript, 0x4680)),
                        f_q
                    )
                )
                {
                    let prod := mload(add(transcript, 0x4760))
                    prod := mulmod(mload(add(transcript, 0x4780)), prod, f_q)
                    mstore(add(transcript, 0x49a0), prod)
                    prod := mulmod(mload(add(transcript, 0x47a0)), prod, f_q)
                    mstore(add(transcript, 0x49c0), prod)
                    prod := mulmod(mload(add(transcript, 0x47c0)), prod, f_q)
                    mstore(add(transcript, 0x49e0), prod)
                    prod := mulmod(mload(add(transcript, 0x4860)), prod, f_q)
                    mstore(add(transcript, 0x4a00), prod)
                    prod := mulmod(mload(add(transcript, 0x47e0)), prod, f_q)
                    mstore(add(transcript, 0x4a20), prod)
                    prod := mulmod(mload(add(transcript, 0x4880)), prod, f_q)
                    mstore(add(transcript, 0x4a40), prod)
                    prod := mulmod(mload(add(transcript, 0x48a0)), prod, f_q)
                    mstore(add(transcript, 0x4a60), prod)
                    prod := mulmod(mload(add(transcript, 0x48c0)), prod, f_q)
                    mstore(add(transcript, 0x4a80), prod)
                    prod := mulmod(mload(add(transcript, 0x48e0)), prod, f_q)
                    mstore(add(transcript, 0x4aa0), prod)
                    prod := mulmod(mload(add(transcript, 0x4900)), prod, f_q)
                    mstore(add(transcript, 0x4ac0), prod)
                    prod := mulmod(mload(add(transcript, 0x4920)), prod, f_q)
                    mstore(add(transcript, 0x4ae0), prod)
                    prod := mulmod(mload(add(transcript, 0x4800)), prod, f_q)
                    mstore(add(transcript, 0x4b00), prod)
                    prod := mulmod(mload(add(transcript, 0x4940)), prod, f_q)
                    mstore(add(transcript, 0x4b20), prod)
                    prod := mulmod(mload(add(transcript, 0x4960)), prod, f_q)
                    mstore(add(transcript, 0x4b40), prod)
                    prod := mulmod(mload(add(transcript, 0x4980)), prod, f_q)
                    mstore(add(transcript, 0x4b60), prod)
                }
            }
        }
        bytes memory transcriptBytes = abi.encode(transcript);
        // bytes32[] memory newTranscript = new bytes32[](1323);
        // for(uint i=0; i<_transcript.length; i++) {
        //     newTranscript[i] = transcript[i];
        // }
        // require(newTranscript.length == 1323, "newTranscript length is not 1323");
        return (success, transcriptBytes);
    }
}
