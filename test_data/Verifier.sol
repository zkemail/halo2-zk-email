// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract Verifier {
    function verify(
        uint256[] memory pubInputs,
        bytes memory proof
    ) public view returns (bool) {
        bool success = true;
        bytes32[1263] memory transcript;
        assembly {
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
                    let is_affine := eq(x_cube_plus_3, y_square)
                    valid := and(valid, is_affine)
                }
            }
            mstore(add(transcript, 0x20), mod(mload(add(pubInputs, 0x20)), f_q))
            mstore(add(transcript, 0x40), mod(mload(add(pubInputs, 0x40)), f_q))
            mstore(add(transcript, 0x60), mod(mload(add(pubInputs, 0x60)), f_q))
            mstore(add(transcript, 0x80), mod(mload(add(pubInputs, 0x80)), f_q))
            mstore(add(transcript, 0xa0), mod(mload(add(pubInputs, 0xa0)), f_q))
            mstore(add(transcript, 0xc0), mod(mload(add(pubInputs, 0xc0)), f_q))
            mstore(add(transcript, 0xe0), mod(mload(add(pubInputs, 0xe0)), f_q))
            mstore(
                add(transcript, 0x100),
                mod(mload(add(pubInputs, 0x100)), f_q)
            )
            mstore(
                add(transcript, 0x120),
                mod(mload(add(pubInputs, 0x120)), f_q)
            )
            mstore(
                add(transcript, 0x140),
                mod(mload(add(pubInputs, 0x140)), f_q)
            )
            mstore(
                add(transcript, 0x160),
                mod(mload(add(pubInputs, 0x160)), f_q)
            )
            mstore(
                add(transcript, 0x180),
                mod(mload(add(pubInputs, 0x180)), f_q)
            )
            mstore(
                add(transcript, 0x1a0),
                mod(mload(add(pubInputs, 0x1a0)), f_q)
            )
            mstore(
                add(transcript, 0x1c0),
                mod(mload(add(pubInputs, 0x1c0)), f_q)
            )
            mstore(
                add(transcript, 0x1e0),
                mod(mload(add(pubInputs, 0x1e0)), f_q)
            )
            mstore(
                add(transcript, 0x200),
                mod(mload(add(pubInputs, 0x200)), f_q)
            )
            mstore(
                add(transcript, 0x220),
                mod(mload(add(pubInputs, 0x220)), f_q)
            )
            mstore(
                add(transcript, 0x0),
                15628270296617880890451399113507799320648942336652371358932276106691715148137
            )
            {
                let x := mload(add(proof, 0x20))
                mstore(add(transcript, 0x240), x)
                let y := mload(add(proof, 0x40))
                mstore(add(transcript, 0x260), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x60))
                mstore(add(transcript, 0x280), x)
                let y := mload(add(proof, 0x80))
                mstore(add(transcript, 0x2a0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0xa0))
                mstore(add(transcript, 0x2c0), x)
                let y := mload(add(proof, 0xc0))
                mstore(add(transcript, 0x2e0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0xe0))
                mstore(add(transcript, 0x300), x)
                let y := mload(add(proof, 0x100))
                mstore(add(transcript, 0x320), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x120))
                mstore(add(transcript, 0x340), x)
                let y := mload(add(proof, 0x140))
                mstore(add(transcript, 0x360), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(add(transcript, 0x380), keccak256(add(transcript, 0x0), 896))
            {
                let hash := mload(add(transcript, 0x380))
                mstore(add(transcript, 0x3a0), mod(hash, f_q))
                mstore(add(transcript, 0x3c0), hash)
            }
            {
                let x := mload(add(proof, 0x160))
                mstore(add(transcript, 0x3e0), x)
                let y := mload(add(proof, 0x180))
                mstore(add(transcript, 0x400), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x1a0))
                mstore(add(transcript, 0x420), x)
                let y := mload(add(proof, 0x1c0))
                mstore(add(transcript, 0x440), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x1e0))
                mstore(add(transcript, 0x460), x)
                let y := mload(add(proof, 0x200))
                mstore(add(transcript, 0x480), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x220))
                mstore(add(transcript, 0x4a0), x)
                let y := mload(add(proof, 0x240))
                mstore(add(transcript, 0x4c0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x260))
                mstore(add(transcript, 0x4e0), x)
                let y := mload(add(proof, 0x280))
                mstore(add(transcript, 0x500), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x2a0))
                mstore(add(transcript, 0x520), x)
                let y := mload(add(proof, 0x2c0))
                mstore(add(transcript, 0x540), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x2e0))
                mstore(add(transcript, 0x560), x)
                let y := mload(add(proof, 0x300))
                mstore(add(transcript, 0x580), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x320))
                mstore(add(transcript, 0x5a0), x)
                let y := mload(add(proof, 0x340))
                mstore(add(transcript, 0x5c0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x360))
                mstore(add(transcript, 0x5e0), x)
                let y := mload(add(proof, 0x380))
                mstore(add(transcript, 0x600), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x3a0))
                mstore(add(transcript, 0x620), x)
                let y := mload(add(proof, 0x3c0))
                mstore(add(transcript, 0x640), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x660),
                keccak256(add(transcript, 0x3c0), 672)
            )
            {
                let hash := mload(add(transcript, 0x660))
                mstore(add(transcript, 0x680), mod(hash, f_q))
                mstore(add(transcript, 0x6a0), hash)
            }
            mstore8(add(transcript, 0x6c0), 1)
            mstore(
                add(transcript, 0x6c0),
                keccak256(add(transcript, 0x6a0), 33)
            )
            {
                let hash := mload(add(transcript, 0x6c0))
                mstore(add(transcript, 0x6e0), mod(hash, f_q))
                mstore(add(transcript, 0x700), hash)
            }
            {
                let x := mload(add(proof, 0x3e0))
                mstore(add(transcript, 0x720), x)
                let y := mload(add(proof, 0x400))
                mstore(add(transcript, 0x740), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x420))
                mstore(add(transcript, 0x760), x)
                let y := mload(add(proof, 0x440))
                mstore(add(transcript, 0x780), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x460))
                mstore(add(transcript, 0x7a0), x)
                let y := mload(add(proof, 0x480))
                mstore(add(transcript, 0x7c0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x4a0))
                mstore(add(transcript, 0x7e0), x)
                let y := mload(add(proof, 0x4c0))
                mstore(add(transcript, 0x800), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x4e0))
                mstore(add(transcript, 0x820), x)
                let y := mload(add(proof, 0x500))
                mstore(add(transcript, 0x840), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x520))
                mstore(add(transcript, 0x860), x)
                let y := mload(add(proof, 0x540))
                mstore(add(transcript, 0x880), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x560))
                mstore(add(transcript, 0x8a0), x)
                let y := mload(add(proof, 0x580))
                mstore(add(transcript, 0x8c0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x5a0))
                mstore(add(transcript, 0x8e0), x)
                let y := mload(add(proof, 0x5c0))
                mstore(add(transcript, 0x900), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x920),
                keccak256(add(transcript, 0x700), 544)
            )
            {
                let hash := mload(add(transcript, 0x920))
                mstore(add(transcript, 0x940), mod(hash, f_q))
                mstore(add(transcript, 0x960), hash)
            }
            {
                let x := mload(add(proof, 0x5e0))
                mstore(add(transcript, 0x980), x)
                let y := mload(add(proof, 0x600))
                mstore(add(transcript, 0x9a0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x620))
                mstore(add(transcript, 0x9c0), x)
                let y := mload(add(proof, 0x640))
                mstore(add(transcript, 0x9e0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x660))
                mstore(add(transcript, 0xa00), x)
                let y := mload(add(proof, 0x680))
                mstore(add(transcript, 0xa20), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x6a0))
                mstore(add(transcript, 0xa40), x)
                let y := mload(add(proof, 0x6c0))
                mstore(add(transcript, 0xa60), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0xa80),
                keccak256(add(transcript, 0x960), 288)
            )
            {
                let hash := mload(add(transcript, 0xa80))
                mstore(add(transcript, 0xaa0), mod(hash, f_q))
                mstore(add(transcript, 0xac0), hash)
            }
            mstore(add(transcript, 0xae0), mod(mload(add(proof, 0x6e0)), f_q))
            mstore(add(transcript, 0xb00), mod(mload(add(proof, 0x700)), f_q))
            mstore(add(transcript, 0xb20), mod(mload(add(proof, 0x720)), f_q))
            mstore(add(transcript, 0xb40), mod(mload(add(proof, 0x740)), f_q))
            mstore(add(transcript, 0xb60), mod(mload(add(proof, 0x760)), f_q))
            mstore(add(transcript, 0xb80), mod(mload(add(proof, 0x780)), f_q))
            mstore(add(transcript, 0xba0), mod(mload(add(proof, 0x7a0)), f_q))
            mstore(add(transcript, 0xbc0), mod(mload(add(proof, 0x7c0)), f_q))
            mstore(add(transcript, 0xbe0), mod(mload(add(proof, 0x7e0)), f_q))
            mstore(add(transcript, 0xc00), mod(mload(add(proof, 0x800)), f_q))
            mstore(add(transcript, 0xc20), mod(mload(add(proof, 0x820)), f_q))
            mstore(add(transcript, 0xc40), mod(mload(add(proof, 0x840)), f_q))
            mstore(add(transcript, 0xc60), mod(mload(add(proof, 0x860)), f_q))
            mstore(add(transcript, 0xc80), mod(mload(add(proof, 0x880)), f_q))
            mstore(add(transcript, 0xca0), mod(mload(add(proof, 0x8a0)), f_q))
            mstore(add(transcript, 0xcc0), mod(mload(add(proof, 0x8c0)), f_q))
            mstore(add(transcript, 0xce0), mod(mload(add(proof, 0x8e0)), f_q))
            mstore(add(transcript, 0xd00), mod(mload(add(proof, 0x900)), f_q))
            mstore(add(transcript, 0xd20), mod(mload(add(proof, 0x920)), f_q))
            mstore(add(transcript, 0xd40), mod(mload(add(proof, 0x940)), f_q))
            mstore(add(transcript, 0xd60), mod(mload(add(proof, 0x960)), f_q))
            mstore(add(transcript, 0xd80), mod(mload(add(proof, 0x980)), f_q))
            mstore(add(transcript, 0xda0), mod(mload(add(proof, 0x9a0)), f_q))
            mstore(add(transcript, 0xdc0), mod(mload(add(proof, 0x9c0)), f_q))
            mstore(add(transcript, 0xde0), mod(mload(add(proof, 0x9e0)), f_q))
            mstore(add(transcript, 0xe00), mod(mload(add(proof, 0xa00)), f_q))
            mstore(add(transcript, 0xe20), mod(mload(add(proof, 0xa20)), f_q))
            mstore(add(transcript, 0xe40), mod(mload(add(proof, 0xa40)), f_q))
            mstore(add(transcript, 0xe60), mod(mload(add(proof, 0xa60)), f_q))
            mstore(add(transcript, 0xe80), mod(mload(add(proof, 0xa80)), f_q))
            mstore(add(transcript, 0xea0), mod(mload(add(proof, 0xaa0)), f_q))
            mstore(add(transcript, 0xec0), mod(mload(add(proof, 0xac0)), f_q))
            mstore(add(transcript, 0xee0), mod(mload(add(proof, 0xae0)), f_q))
            mstore(add(transcript, 0xf00), mod(mload(add(proof, 0xb00)), f_q))
            mstore(add(transcript, 0xf20), mod(mload(add(proof, 0xb20)), f_q))
            mstore(add(transcript, 0xf40), mod(mload(add(proof, 0xb40)), f_q))
            mstore(add(transcript, 0xf60), mod(mload(add(proof, 0xb60)), f_q))
            mstore(add(transcript, 0xf80), mod(mload(add(proof, 0xb80)), f_q))
            mstore(add(transcript, 0xfa0), mod(mload(add(proof, 0xba0)), f_q))
            mstore(add(transcript, 0xfc0), mod(mload(add(proof, 0xbc0)), f_q))
            mstore(add(transcript, 0xfe0), mod(mload(add(proof, 0xbe0)), f_q))
            mstore(add(transcript, 0x1000), mod(mload(add(proof, 0xc00)), f_q))
            mstore(add(transcript, 0x1020), mod(mload(add(proof, 0xc20)), f_q))
            mstore(add(transcript, 0x1040), mod(mload(add(proof, 0xc40)), f_q))
            mstore(add(transcript, 0x1060), mod(mload(add(proof, 0xc60)), f_q))
            mstore(add(transcript, 0x1080), mod(mload(add(proof, 0xc80)), f_q))
            mstore(add(transcript, 0x10a0), mod(mload(add(proof, 0xca0)), f_q))
            mstore(add(transcript, 0x10c0), mod(mload(add(proof, 0xcc0)), f_q))
            mstore(add(transcript, 0x10e0), mod(mload(add(proof, 0xce0)), f_q))
            mstore(add(transcript, 0x1100), mod(mload(add(proof, 0xd00)), f_q))
            mstore(add(transcript, 0x1120), mod(mload(add(proof, 0xd20)), f_q))
            mstore(add(transcript, 0x1140), mod(mload(add(proof, 0xd40)), f_q))
            mstore(add(transcript, 0x1160), mod(mload(add(proof, 0xd60)), f_q))
            mstore(add(transcript, 0x1180), mod(mload(add(proof, 0xd80)), f_q))
            mstore(add(transcript, 0x11a0), mod(mload(add(proof, 0xda0)), f_q))
            mstore(add(transcript, 0x11c0), mod(mload(add(proof, 0xdc0)), f_q))
            mstore(add(transcript, 0x11e0), mod(mload(add(proof, 0xde0)), f_q))
            mstore(
                add(transcript, 0x1200),
                keccak256(add(transcript, 0xac0), 1856)
            )
            {
                let hash := mload(add(transcript, 0x1200))
                mstore(add(transcript, 0x1220), mod(hash, f_q))
                mstore(add(transcript, 0x1240), hash)
            }
            {
                let x := mload(add(proof, 0xe00))
                mstore(add(transcript, 0x1260), x)
                let y := mload(add(proof, 0xe20))
                mstore(add(transcript, 0x1280), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0xe40))
                mstore(add(transcript, 0x12a0), x)
                let y := mload(add(proof, 0xe60))
                mstore(add(transcript, 0x12c0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0xe80))
                mstore(add(transcript, 0x12e0), x)
                let y := mload(add(proof, 0xea0))
                mstore(add(transcript, 0x1300), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0xec0))
                mstore(add(transcript, 0x1320), x)
                let y := mload(add(proof, 0xee0))
                mstore(add(transcript, 0x1340), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x1360),
                keccak256(add(transcript, 0x1240), 288)
            )
            {
                let hash := mload(add(transcript, 0x1360))
                mstore(add(transcript, 0x1380), mod(hash, f_q))
                mstore(add(transcript, 0x13a0), hash)
            }
            {
                let x := mload(add(transcript, 0x20))
                x := add(x, shl(68, mload(add(transcript, 0x40))))
                x := add(x, shl(136, mload(add(transcript, 0x60))))
                x := add(x, shl(204, mload(add(transcript, 0x80))))
                mstore(add(transcript, 0x13c0), x)
                let y := mload(add(transcript, 0xa0))
                y := add(y, shl(68, mload(add(transcript, 0xc0))))
                y := add(y, shl(136, mload(add(transcript, 0xe0))))
                y := add(y, shl(204, mload(add(transcript, 0x100))))
                mstore(add(transcript, 0x13e0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(transcript, 0x120))
                x := add(x, shl(68, mload(add(transcript, 0x140))))
                x := add(x, shl(136, mload(add(transcript, 0x160))))
                x := add(x, shl(204, mload(add(transcript, 0x180))))
                mstore(add(transcript, 0x1400), x)
                let y := mload(add(transcript, 0x1a0))
                y := add(y, shl(68, mload(add(transcript, 0x1c0))))
                y := add(y, shl(136, mload(add(transcript, 0x1e0))))
                y := add(y, shl(204, mload(add(transcript, 0x200))))
                mstore(add(transcript, 0x1420), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x1440),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1460),
                mulmod(
                    mload(add(transcript, 0x1440)),
                    mload(add(transcript, 0x1440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1480),
                mulmod(
                    mload(add(transcript, 0x1460)),
                    mload(add(transcript, 0x1460)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14a0),
                mulmod(
                    mload(add(transcript, 0x1480)),
                    mload(add(transcript, 0x1480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14c0),
                mulmod(
                    mload(add(transcript, 0x14a0)),
                    mload(add(transcript, 0x14a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14e0),
                mulmod(
                    mload(add(transcript, 0x14c0)),
                    mload(add(transcript, 0x14c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1500),
                mulmod(
                    mload(add(transcript, 0x14e0)),
                    mload(add(transcript, 0x14e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1520),
                mulmod(
                    mload(add(transcript, 0x1500)),
                    mload(add(transcript, 0x1500)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1540),
                mulmod(
                    mload(add(transcript, 0x1520)),
                    mload(add(transcript, 0x1520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1560),
                mulmod(
                    mload(add(transcript, 0x1540)),
                    mload(add(transcript, 0x1540)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1580),
                mulmod(
                    mload(add(transcript, 0x1560)),
                    mload(add(transcript, 0x1560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15a0),
                mulmod(
                    mload(add(transcript, 0x1580)),
                    mload(add(transcript, 0x1580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15c0),
                mulmod(
                    mload(add(transcript, 0x15a0)),
                    mload(add(transcript, 0x15a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15e0),
                mulmod(
                    mload(add(transcript, 0x15c0)),
                    mload(add(transcript, 0x15c0)),
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
                addmod(
                    mload(add(transcript, 0x1720)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1760),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    21888241567198334088790460357988866238279339518792980768180410072331574733841,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1780),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    14655294445420895451632927078981340937842238432098198055057679026789553137428,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17a0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    7232948426418379770613478666275934150706125968317836288640525159786255358189,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17c0),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    12220484078924208264862893648548198807365556694478604924193442790112568454894,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17e0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    9667758792915066957383512096709076281182807705937429419504761396463240040723,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1800),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    8734126352828345679573237859165904705806588461301144420590422589042130041188,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1820),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    13154116519010929542673167886091370382741775939114889923107781597533678454429,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1840),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    7358966525675286471217089135633860168646304224547606326237275077574224349359,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1860),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    14529276346163988751029316609623414919902060175868428017460929109001584146258,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1880),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    9741553891420464328295280489650144566903017206473301385034033384879943874347,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18a0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    12146688980418810893951125255607130521645347193942732958664170801695864621270,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18c0),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    17329448237240114492580865744088056414251735686965494637158808787419781175510,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18e0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    4558794634599160729665540001169218674296628713450539706539395399156027320107,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1900),
                mulmod(mload(add(transcript, 0x1760)), 1, f_q)
            )
            mstore(
                add(transcript, 0x1920),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1940),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    11451405578697956743456240853980216273390554734748796433026540431386972584651,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1960),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    10436837293141318478790164891277058815157809665667237910671663755188835910966,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1980),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    8374374965308410102411073611984011876711565317741801500439755773472076597347,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19a0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    13513867906530865119835332133273263211836799082674232843258448413103731898270,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19c0),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    21490807004895109926141140246143262403290679459142140821740925192625185504522,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19e0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    397435866944165296105265499114012685257684941273893521957278993950622991095,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a00),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    11211301017135681023579411905410872569206244553457844956874280139879520583390,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a20),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    10676941854703594198666993839846402519342119846958189386823924046696287912227,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a40),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    18846108080730935585192484934247867403156699586319724728525857970312957475341,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a60),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    3042134791108339637053920811009407685391664814096309615172346216262851020276,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a80),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    3615478808282855240548287271348143516886772452944084747768312988864436725401,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1aa0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    18272764063556419981698118473909131571661591947471949595929891197711371770216,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ac0),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    21451937155080765789602997556105366785934335730087568134349216848800867145453,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ae0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    436305716758509432643408189151908302614028670328466209348987337774941350164,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b00),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    1426404432721484388505361748317961535523355871255605456897797744433766488507,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b20),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    20461838439117790833741043996939313553025008529160428886800406442142042007110,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b40),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    13982290267294411190096162596630216412723378687553046594730793425118513274800,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b60),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    7905952604544864032150243148627058675824985712862987748967410761457295220817,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b80),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    216092043779272773661818549620449970334216366264741118684015851799902419467,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ba0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    21672150828060002448584587195636825118214148034151293225014188334775906076150,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1bc0),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    9537783784440837896026284659246718978615447564543116209283382057778110278482,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1be0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    12350459087398437326220121086010556109932916835872918134414822128797698217135,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c00),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    12619617507853212586156872920672483948819476989779550311307282715684870266992,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c20),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    9268625363986062636089532824584791139728887410636484032390921470890938228625,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c40),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    3947443723575973965644279767310964219908423994086470065513888332899718123222,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c60),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    17940799148263301256602125977946310868639940406329564278184315853676090372395,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c80),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    18610195890048912503953886742825279624920778288956610528523679659246523534888,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ca0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    3278046981790362718292519002431995463627586111459423815174524527329284960729,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1cc0),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    1539082509056298927655194235755440186888826897239928178265486731666142403222,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ce0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    20349160362782976294591211509501834901659537503176106165432717454909666092395,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d00),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    19032961837237948602743626455740240236231119053033140765040043513661803148152,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d20),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    2855281034601326619502779289517034852317245347382893578658160672914005347465,
                    f_q
                )
            )
            {
                let prod := mload(add(transcript, 0x17a0))
                prod := mulmod(mload(add(transcript, 0x17e0)), prod, f_q)
                mstore(add(transcript, 0x1d40), prod)
                prod := mulmod(mload(add(transcript, 0x1820)), prod, f_q)
                mstore(add(transcript, 0x1d60), prod)
                prod := mulmod(mload(add(transcript, 0x1860)), prod, f_q)
                mstore(add(transcript, 0x1d80), prod)
                prod := mulmod(mload(add(transcript, 0x18a0)), prod, f_q)
                mstore(add(transcript, 0x1da0), prod)
                prod := mulmod(mload(add(transcript, 0x18e0)), prod, f_q)
                mstore(add(transcript, 0x1dc0), prod)
                prod := mulmod(mload(add(transcript, 0x1920)), prod, f_q)
                mstore(add(transcript, 0x1de0), prod)
                prod := mulmod(mload(add(transcript, 0x1960)), prod, f_q)
                mstore(add(transcript, 0x1e00), prod)
                prod := mulmod(mload(add(transcript, 0x19a0)), prod, f_q)
                mstore(add(transcript, 0x1e20), prod)
                prod := mulmod(mload(add(transcript, 0x19e0)), prod, f_q)
                mstore(add(transcript, 0x1e40), prod)
                prod := mulmod(mload(add(transcript, 0x1a20)), prod, f_q)
                mstore(add(transcript, 0x1e60), prod)
                prod := mulmod(mload(add(transcript, 0x1a60)), prod, f_q)
                mstore(add(transcript, 0x1e80), prod)
                prod := mulmod(mload(add(transcript, 0x1aa0)), prod, f_q)
                mstore(add(transcript, 0x1ea0), prod)
                prod := mulmod(mload(add(transcript, 0x1ae0)), prod, f_q)
                mstore(add(transcript, 0x1ec0), prod)
                prod := mulmod(mload(add(transcript, 0x1b20)), prod, f_q)
                mstore(add(transcript, 0x1ee0), prod)
                prod := mulmod(mload(add(transcript, 0x1b60)), prod, f_q)
                mstore(add(transcript, 0x1f00), prod)
                prod := mulmod(mload(add(transcript, 0x1ba0)), prod, f_q)
                mstore(add(transcript, 0x1f20), prod)
                prod := mulmod(mload(add(transcript, 0x1be0)), prod, f_q)
                mstore(add(transcript, 0x1f40), prod)
                prod := mulmod(mload(add(transcript, 0x1c20)), prod, f_q)
                mstore(add(transcript, 0x1f60), prod)
                prod := mulmod(mload(add(transcript, 0x1c60)), prod, f_q)
                mstore(add(transcript, 0x1f80), prod)
                prod := mulmod(mload(add(transcript, 0x1ca0)), prod, f_q)
                mstore(add(transcript, 0x1fa0), prod)
                prod := mulmod(mload(add(transcript, 0x1ce0)), prod, f_q)
                mstore(add(transcript, 0x1fc0), prod)
                prod := mulmod(mload(add(transcript, 0x1d20)), prod, f_q)
                mstore(add(transcript, 0x1fe0), prod)
                prod := mulmod(mload(add(transcript, 0x1740)), prod, f_q)
                mstore(add(transcript, 0x2000), prod)
            }
            mstore(add(transcript, 0x2040), 32)
            mstore(add(transcript, 0x2060), 32)
            mstore(add(transcript, 0x2080), 32)
            mstore(add(transcript, 0x20a0), mload(add(transcript, 0x2000)))
            mstore(
                add(transcript, 0x20c0),
                21888242871839275222246405745257275088548364400416034343698204186575808495615
            )
            mstore(
                add(transcript, 0x20e0),
                21888242871839275222246405745257275088548364400416034343698204186575808495617
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x5,
                        add(transcript, 0x2040),
                        0xc0,
                        add(transcript, 0x2020),
                        0x20
                    ),
                    1
                ),
                success
            )
            {
                let inv := mload(add(transcript, 0x2020))
                let v
                v := mload(add(transcript, 0x1740))
                mstore(
                    add(transcript, 0x1740),
                    mulmod(mload(add(transcript, 0x1fe0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1d20))
                mstore(
                    add(transcript, 0x1d20),
                    mulmod(mload(add(transcript, 0x1fc0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1ce0))
                mstore(
                    add(transcript, 0x1ce0),
                    mulmod(mload(add(transcript, 0x1fa0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1ca0))
                mstore(
                    add(transcript, 0x1ca0),
                    mulmod(mload(add(transcript, 0x1f80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1c60))
                mstore(
                    add(transcript, 0x1c60),
                    mulmod(mload(add(transcript, 0x1f60)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1c20))
                mstore(
                    add(transcript, 0x1c20),
                    mulmod(mload(add(transcript, 0x1f40)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1be0))
                mstore(
                    add(transcript, 0x1be0),
                    mulmod(mload(add(transcript, 0x1f20)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1ba0))
                mstore(
                    add(transcript, 0x1ba0),
                    mulmod(mload(add(transcript, 0x1f00)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1b60))
                mstore(
                    add(transcript, 0x1b60),
                    mulmod(mload(add(transcript, 0x1ee0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1b20))
                mstore(
                    add(transcript, 0x1b20),
                    mulmod(mload(add(transcript, 0x1ec0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1ae0))
                mstore(
                    add(transcript, 0x1ae0),
                    mulmod(mload(add(transcript, 0x1ea0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1aa0))
                mstore(
                    add(transcript, 0x1aa0),
                    mulmod(mload(add(transcript, 0x1e80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1a60))
                mstore(
                    add(transcript, 0x1a60),
                    mulmod(mload(add(transcript, 0x1e60)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1a20))
                mstore(
                    add(transcript, 0x1a20),
                    mulmod(mload(add(transcript, 0x1e40)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x19e0))
                mstore(
                    add(transcript, 0x19e0),
                    mulmod(mload(add(transcript, 0x1e20)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x19a0))
                mstore(
                    add(transcript, 0x19a0),
                    mulmod(mload(add(transcript, 0x1e00)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1960))
                mstore(
                    add(transcript, 0x1960),
                    mulmod(mload(add(transcript, 0x1de0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1920))
                mstore(
                    add(transcript, 0x1920),
                    mulmod(mload(add(transcript, 0x1dc0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x18e0))
                mstore(
                    add(transcript, 0x18e0),
                    mulmod(mload(add(transcript, 0x1da0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x18a0))
                mstore(
                    add(transcript, 0x18a0),
                    mulmod(mload(add(transcript, 0x1d80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1860))
                mstore(
                    add(transcript, 0x1860),
                    mulmod(mload(add(transcript, 0x1d60)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1820))
                mstore(
                    add(transcript, 0x1820),
                    mulmod(mload(add(transcript, 0x1d40)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x17e0))
                mstore(
                    add(transcript, 0x17e0),
                    mulmod(mload(add(transcript, 0x17a0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                mstore(add(transcript, 0x17a0), inv)
            }
            mstore(
                add(transcript, 0x2100),
                mulmod(
                    mload(add(transcript, 0x1780)),
                    mload(add(transcript, 0x17a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2120),
                mulmod(
                    mload(add(transcript, 0x17c0)),
                    mload(add(transcript, 0x17e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2140),
                mulmod(
                    mload(add(transcript, 0x1800)),
                    mload(add(transcript, 0x1820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2160),
                mulmod(
                    mload(add(transcript, 0x1840)),
                    mload(add(transcript, 0x1860)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2180),
                mulmod(
                    mload(add(transcript, 0x1880)),
                    mload(add(transcript, 0x18a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21a0),
                mulmod(
                    mload(add(transcript, 0x18c0)),
                    mload(add(transcript, 0x18e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21c0),
                mulmod(
                    mload(add(transcript, 0x1900)),
                    mload(add(transcript, 0x1920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21e0),
                mulmod(
                    mload(add(transcript, 0x1940)),
                    mload(add(transcript, 0x1960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2200),
                mulmod(
                    mload(add(transcript, 0x1980)),
                    mload(add(transcript, 0x19a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2220),
                mulmod(
                    mload(add(transcript, 0x19c0)),
                    mload(add(transcript, 0x19e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2240),
                mulmod(
                    mload(add(transcript, 0x1a00)),
                    mload(add(transcript, 0x1a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2260),
                mulmod(
                    mload(add(transcript, 0x1a40)),
                    mload(add(transcript, 0x1a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2280),
                mulmod(
                    mload(add(transcript, 0x1a80)),
                    mload(add(transcript, 0x1aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22a0),
                mulmod(
                    mload(add(transcript, 0x1ac0)),
                    mload(add(transcript, 0x1ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22c0),
                mulmod(
                    mload(add(transcript, 0x1b00)),
                    mload(add(transcript, 0x1b20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22e0),
                mulmod(
                    mload(add(transcript, 0x1b40)),
                    mload(add(transcript, 0x1b60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2300),
                mulmod(
                    mload(add(transcript, 0x1b80)),
                    mload(add(transcript, 0x1ba0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2320),
                mulmod(
                    mload(add(transcript, 0x1bc0)),
                    mload(add(transcript, 0x1be0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2340),
                mulmod(
                    mload(add(transcript, 0x1c00)),
                    mload(add(transcript, 0x1c20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2360),
                mulmod(
                    mload(add(transcript, 0x1c40)),
                    mload(add(transcript, 0x1c60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2380),
                mulmod(
                    mload(add(transcript, 0x1c80)),
                    mload(add(transcript, 0x1ca0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23a0),
                mulmod(
                    mload(add(transcript, 0x1cc0)),
                    mload(add(transcript, 0x1ce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23c0),
                mulmod(
                    mload(add(transcript, 0x1d00)),
                    mload(add(transcript, 0x1d20)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x21c0)),
                    mload(add(transcript, 0x20)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x21e0)),
                        mload(add(transcript, 0x40)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2200)),
                        mload(add(transcript, 0x60)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2220)),
                        mload(add(transcript, 0x80)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2240)),
                        mload(add(transcript, 0xa0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2260)),
                        mload(add(transcript, 0xc0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2280)),
                        mload(add(transcript, 0xe0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x22a0)),
                        mload(add(transcript, 0x100)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x22c0)),
                        mload(add(transcript, 0x120)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x22e0)),
                        mload(add(transcript, 0x140)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2300)),
                        mload(add(transcript, 0x160)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2320)),
                        mload(add(transcript, 0x180)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2340)),
                        mload(add(transcript, 0x1a0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2360)),
                        mload(add(transcript, 0x1c0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2380)),
                        mload(add(transcript, 0x1e0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x23a0)),
                        mload(add(transcript, 0x200)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x23c0)),
                        mload(add(transcript, 0x220)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x23e0), result)
            }
            mstore(
                add(transcript, 0x2400),
                mulmod(
                    mload(add(transcript, 0xba0)),
                    mload(add(transcript, 0xae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2420),
                mulmod(
                    mload(add(transcript, 0xbc0)),
                    mload(add(transcript, 0xb00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2440),
                addmod(
                    mload(add(transcript, 0x2400)),
                    mload(add(transcript, 0x2420)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2460),
                mulmod(
                    mload(add(transcript, 0xbe0)),
                    mload(add(transcript, 0xb20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2480),
                addmod(
                    mload(add(transcript, 0x2440)),
                    mload(add(transcript, 0x2460)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24a0),
                mulmod(
                    mload(add(transcript, 0xc00)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24c0),
                addmod(
                    mload(add(transcript, 0x2480)),
                    mload(add(transcript, 0x24a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24e0),
                mulmod(
                    mload(add(transcript, 0xc20)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2500),
                addmod(
                    mload(add(transcript, 0x24c0)),
                    mload(add(transcript, 0x24e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2520),
                mulmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0xae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2540),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    mload(add(transcript, 0x2520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2560),
                addmod(
                    mload(add(transcript, 0x2500)),
                    mload(add(transcript, 0x2540)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2580),
                mulmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0xb20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25a0),
                mulmod(
                    mload(add(transcript, 0xc80)),
                    mload(add(transcript, 0x2580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25c0),
                addmod(
                    mload(add(transcript, 0x2560)),
                    mload(add(transcript, 0x25a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25e0),
                mulmod(
                    mload(add(transcript, 0xb80)),
                    mload(add(transcript, 0xc40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2600),
                addmod(
                    mload(add(transcript, 0x25c0)),
                    mload(add(transcript, 0x25e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2620),
                addmod(
                    mload(add(transcript, 0x2600)),
                    mload(add(transcript, 0xca0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2640),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x2620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2660),
                addmod(1, sub(f_q, mload(add(transcript, 0xe40))), f_q)
            )
            mstore(
                add(transcript, 0x2680),
                mulmod(
                    mload(add(transcript, 0x2660)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26a0),
                addmod(
                    mload(add(transcript, 0x2640)),
                    mload(add(transcript, 0x2680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26c0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x26a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26e0),
                mulmod(
                    mload(add(transcript, 0xea0)),
                    mload(add(transcript, 0xea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2700),
                addmod(
                    mload(add(transcript, 0x26e0)),
                    sub(f_q, mload(add(transcript, 0xea0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2720),
                mulmod(
                    mload(add(transcript, 0x2700)),
                    mload(add(transcript, 0x2100)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2740),
                addmod(
                    mload(add(transcript, 0x26c0)),
                    mload(add(transcript, 0x2720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2760),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x2740)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2780),
                addmod(
                    mload(add(transcript, 0xea0)),
                    sub(f_q, mload(add(transcript, 0xe80))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27a0),
                mulmod(
                    mload(add(transcript, 0x2780)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27c0),
                addmod(
                    mload(add(transcript, 0x2760)),
                    mload(add(transcript, 0x27a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27e0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x27c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2800),
                addmod(1, sub(f_q, mload(add(transcript, 0x2100))), f_q)
            )
            mstore(
                add(transcript, 0x2820),
                addmod(
                    mload(add(transcript, 0x2120)),
                    mload(add(transcript, 0x2140)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2840),
                addmod(
                    mload(add(transcript, 0x2820)),
                    mload(add(transcript, 0x2160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2860),
                addmod(
                    mload(add(transcript, 0x2840)),
                    mload(add(transcript, 0x2180)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2880),
                addmod(
                    mload(add(transcript, 0x2860)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28a0),
                addmod(
                    mload(add(transcript, 0x2800)),
                    sub(f_q, mload(add(transcript, 0x2880))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28c0),
                mulmod(
                    mload(add(transcript, 0xd80)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28e0),
                addmod(
                    mload(add(transcript, 0xae0)),
                    mload(add(transcript, 0x28c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2900),
                addmod(
                    mload(add(transcript, 0x28e0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2920),
                mulmod(
                    mload(add(transcript, 0xda0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2940),
                addmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0x2920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2960),
                addmod(
                    mload(add(transcript, 0x2940)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2980),
                mulmod(
                    mload(add(transcript, 0x2960)),
                    mload(add(transcript, 0x2900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29a0),
                mulmod(
                    mload(add(transcript, 0xdc0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29c0),
                addmod(
                    mload(add(transcript, 0xb20)),
                    mload(add(transcript, 0x29a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29e0),
                addmod(
                    mload(add(transcript, 0x29c0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a00),
                mulmod(
                    mload(add(transcript, 0x29e0)),
                    mload(add(transcript, 0x2980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a20),
                mulmod(
                    mload(add(transcript, 0x2a00)),
                    mload(add(transcript, 0xe60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a40),
                mulmod(1, mload(add(transcript, 0x680)), f_q)
            )
            mstore(
                add(transcript, 0x2a60),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a80),
                addmod(
                    mload(add(transcript, 0xae0)),
                    mload(add(transcript, 0x2a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2aa0),
                addmod(
                    mload(add(transcript, 0x2a80)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ac0),
                mulmod(
                    4131629893567559867359510883348571134090853742863529169391034518566172092834,
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ae0),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b00),
                addmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0x2ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b20),
                addmod(
                    mload(add(transcript, 0x2b00)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b40),
                mulmod(
                    mload(add(transcript, 0x2b20)),
                    mload(add(transcript, 0x2aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b60),
                mulmod(
                    8910878055287538404433155982483128285667088683464058436815641868457422632747,
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b80),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2b60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ba0),
                addmod(
                    mload(add(transcript, 0xb20)),
                    mload(add(transcript, 0x2b80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2bc0),
                addmod(
                    mload(add(transcript, 0x2ba0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2be0),
                mulmod(
                    mload(add(transcript, 0x2bc0)),
                    mload(add(transcript, 0x2b40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c00),
                mulmod(
                    mload(add(transcript, 0x2be0)),
                    mload(add(transcript, 0xe40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c20),
                addmod(
                    mload(add(transcript, 0x2a20)),
                    sub(f_q, mload(add(transcript, 0x2c00))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c40),
                mulmod(
                    mload(add(transcript, 0x2c20)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c60),
                addmod(
                    mload(add(transcript, 0x27e0)),
                    mload(add(transcript, 0x2c40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c80),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x2c60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ca0),
                mulmod(
                    mload(add(transcript, 0xde0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2cc0),
                addmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0x2ca0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ce0),
                addmod(
                    mload(add(transcript, 0x2cc0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d00),
                mulmod(
                    mload(add(transcript, 0xe00)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d20),
                addmod(
                    mload(add(transcript, 0xb60)),
                    mload(add(transcript, 0x2d00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d40),
                addmod(
                    mload(add(transcript, 0x2d20)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d60),
                mulmod(
                    mload(add(transcript, 0x2d40)),
                    mload(add(transcript, 0x2ce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d80),
                mulmod(
                    mload(add(transcript, 0xe20)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2da0),
                addmod(
                    mload(add(transcript, 0x23e0)),
                    mload(add(transcript, 0x2d80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2dc0),
                addmod(
                    mload(add(transcript, 0x2da0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2de0),
                mulmod(
                    mload(add(transcript, 0x2dc0)),
                    mload(add(transcript, 0x2d60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e00),
                mulmod(
                    mload(add(transcript, 0x2de0)),
                    mload(add(transcript, 0xec0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e20),
                mulmod(
                    11166246659983828508719468090013646171463329086121580628794302409516816350802,
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e40),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2e20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e60),
                addmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0x2e40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e80),
                addmod(
                    mload(add(transcript, 0x2e60)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ea0),
                mulmod(
                    284840088355319032285349970403338060113257071685626700086398481893096618818,
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ec0),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2ea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ee0),
                addmod(
                    mload(add(transcript, 0xb60)),
                    mload(add(transcript, 0x2ec0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f00),
                addmod(
                    mload(add(transcript, 0x2ee0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f20),
                mulmod(
                    mload(add(transcript, 0x2f00)),
                    mload(add(transcript, 0x2e80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f40),
                mulmod(
                    21134065618345176623193549882539580312263652408302468683943992798037078993309,
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f60),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2f40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f80),
                addmod(
                    mload(add(transcript, 0x23e0)),
                    mload(add(transcript, 0x2f60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fa0),
                addmod(
                    mload(add(transcript, 0x2f80)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fc0),
                mulmod(
                    mload(add(transcript, 0x2fa0)),
                    mload(add(transcript, 0x2f20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fe0),
                mulmod(
                    mload(add(transcript, 0x2fc0)),
                    mload(add(transcript, 0xea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3000),
                addmod(
                    mload(add(transcript, 0x2e00)),
                    sub(f_q, mload(add(transcript, 0x2fe0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3020),
                mulmod(
                    mload(add(transcript, 0x3000)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3040),
                addmod(
                    mload(add(transcript, 0x2c80)),
                    mload(add(transcript, 0x3020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3060),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3040)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3080),
                addmod(1, sub(f_q, mload(add(transcript, 0xee0))), f_q)
            )
            mstore(
                add(transcript, 0x30a0),
                mulmod(
                    mload(add(transcript, 0x3080)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x30c0),
                addmod(
                    mload(add(transcript, 0x3060)),
                    mload(add(transcript, 0x30a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x30e0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x30c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3100),
                mulmod(
                    mload(add(transcript, 0xee0)),
                    mload(add(transcript, 0xee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3120),
                addmod(
                    mload(add(transcript, 0x3100)),
                    sub(f_q, mload(add(transcript, 0xee0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3140),
                mulmod(
                    mload(add(transcript, 0x3120)),
                    mload(add(transcript, 0x2100)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3160),
                addmod(
                    mload(add(transcript, 0x30e0)),
                    mload(add(transcript, 0x3140)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3180),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x31a0),
                addmod(
                    mload(add(transcript, 0xf20)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x31c0),
                mulmod(
                    mload(add(transcript, 0x31a0)),
                    mload(add(transcript, 0xf00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x31e0),
                addmod(
                    mload(add(transcript, 0xf60)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3200),
                mulmod(
                    mload(add(transcript, 0x31e0)),
                    mload(add(transcript, 0x31c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3220),
                mulmod(5, mload(add(transcript, 0xd20)), f_q)
            )
            mstore(
                add(transcript, 0x3240),
                mulmod(
                    mload(add(transcript, 0x3a0)),
                    mload(add(transcript, 0x3220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3260),
                mulmod(
                    mload(add(transcript, 0xae0)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3280),
                addmod(
                    mload(add(transcript, 0x3240)),
                    mload(add(transcript, 0x3260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x32a0),
                addmod(
                    mload(add(transcript, 0x3280)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x32c0),
                mulmod(
                    mload(add(transcript, 0x32a0)),
                    mload(add(transcript, 0xee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x32e0),
                mulmod(
                    mload(add(transcript, 0x3a0)),
                    mload(add(transcript, 0xcc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3300),
                addmod(
                    mload(add(transcript, 0x32e0)),
                    mload(add(transcript, 0xce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3320),
                addmod(
                    mload(add(transcript, 0x3300)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3340),
                mulmod(
                    mload(add(transcript, 0x3320)),
                    mload(add(transcript, 0x32c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3360),
                addmod(
                    mload(add(transcript, 0x3200)),
                    sub(f_q, mload(add(transcript, 0x3340))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3380),
                mulmod(
                    mload(add(transcript, 0x3360)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x33a0),
                addmod(
                    mload(add(transcript, 0x3180)),
                    mload(add(transcript, 0x3380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x33c0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x33a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x33e0),
                addmod(
                    mload(add(transcript, 0xf20)),
                    sub(f_q, mload(add(transcript, 0xf60))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3400),
                mulmod(
                    mload(add(transcript, 0x33e0)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3420),
                addmod(
                    mload(add(transcript, 0x33c0)),
                    mload(add(transcript, 0x3400)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3440),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3420)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3460),
                mulmod(
                    mload(add(transcript, 0x33e0)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3480),
                addmod(
                    mload(add(transcript, 0xf20)),
                    sub(f_q, mload(add(transcript, 0xf40))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x34a0),
                mulmod(
                    mload(add(transcript, 0x3480)),
                    mload(add(transcript, 0x3460)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x34c0),
                addmod(
                    mload(add(transcript, 0x3440)),
                    mload(add(transcript, 0x34a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x34e0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x34c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3500),
                addmod(1, sub(f_q, mload(add(transcript, 0xf80))), f_q)
            )
            mstore(
                add(transcript, 0x3520),
                mulmod(
                    mload(add(transcript, 0x3500)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3540),
                addmod(
                    mload(add(transcript, 0x34e0)),
                    mload(add(transcript, 0x3520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3560),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3540)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3580),
                mulmod(
                    mload(add(transcript, 0xf80)),
                    mload(add(transcript, 0xf80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x35a0),
                addmod(
                    mload(add(transcript, 0x3580)),
                    sub(f_q, mload(add(transcript, 0xf80))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x35c0),
                mulmod(
                    mload(add(transcript, 0x35a0)),
                    mload(add(transcript, 0x2100)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x35e0),
                addmod(
                    mload(add(transcript, 0x3560)),
                    mload(add(transcript, 0x35c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3600),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x35e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3620),
                addmod(
                    mload(add(transcript, 0xfc0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3640),
                mulmod(
                    mload(add(transcript, 0x3620)),
                    mload(add(transcript, 0xfa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3660),
                addmod(
                    mload(add(transcript, 0x1000)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3680),
                mulmod(
                    mload(add(transcript, 0x3660)),
                    mload(add(transcript, 0x3640)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x36a0),
                mulmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x36c0),
                addmod(
                    mload(add(transcript, 0x3240)),
                    mload(add(transcript, 0x36a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x36e0),
                addmod(
                    mload(add(transcript, 0x36c0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3700),
                mulmod(
                    mload(add(transcript, 0x36e0)),
                    mload(add(transcript, 0xf80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3720),
                mulmod(
                    mload(add(transcript, 0x3320)),
                    mload(add(transcript, 0x3700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3740),
                addmod(
                    mload(add(transcript, 0x3680)),
                    sub(f_q, mload(add(transcript, 0x3720))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3760),
                mulmod(
                    mload(add(transcript, 0x3740)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3780),
                addmod(
                    mload(add(transcript, 0x3600)),
                    mload(add(transcript, 0x3760)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x37a0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x37c0),
                addmod(
                    mload(add(transcript, 0xfc0)),
                    sub(f_q, mload(add(transcript, 0x1000))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x37e0),
                mulmod(
                    mload(add(transcript, 0x37c0)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3800),
                addmod(
                    mload(add(transcript, 0x37a0)),
                    mload(add(transcript, 0x37e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3820),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3840),
                mulmod(
                    mload(add(transcript, 0x37c0)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3860),
                addmod(
                    mload(add(transcript, 0xfc0)),
                    sub(f_q, mload(add(transcript, 0xfe0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3880),
                mulmod(
                    mload(add(transcript, 0x3860)),
                    mload(add(transcript, 0x3840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38a0),
                addmod(
                    mload(add(transcript, 0x3820)),
                    mload(add(transcript, 0x3880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38c0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x38a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38e0),
                addmod(1, sub(f_q, mload(add(transcript, 0x1020))), f_q)
            )
            mstore(
                add(transcript, 0x3900),
                mulmod(
                    mload(add(transcript, 0x38e0)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3920),
                addmod(
                    mload(add(transcript, 0x38c0)),
                    mload(add(transcript, 0x3900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3940),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3960),
                mulmod(
                    mload(add(transcript, 0x1020)),
                    mload(add(transcript, 0x1020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3980),
                addmod(
                    mload(add(transcript, 0x3960)),
                    sub(f_q, mload(add(transcript, 0x1020))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39a0),
                mulmod(
                    mload(add(transcript, 0x3980)),
                    mload(add(transcript, 0x2100)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39c0),
                addmod(
                    mload(add(transcript, 0x3940)),
                    mload(add(transcript, 0x39a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39e0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x39c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a00),
                addmod(
                    mload(add(transcript, 0x1060)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a20),
                mulmod(
                    mload(add(transcript, 0x3a00)),
                    mload(add(transcript, 0x1040)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a40),
                addmod(
                    mload(add(transcript, 0x10a0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a60),
                mulmod(
                    mload(add(transcript, 0x3a40)),
                    mload(add(transcript, 0x3a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a80),
                mulmod(
                    mload(add(transcript, 0xb20)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3aa0),
                addmod(
                    mload(add(transcript, 0x3240)),
                    mload(add(transcript, 0x3a80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ac0),
                addmod(
                    mload(add(transcript, 0x3aa0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ae0),
                mulmod(
                    mload(add(transcript, 0x3ac0)),
                    mload(add(transcript, 0x1020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b00),
                mulmod(
                    mload(add(transcript, 0x3320)),
                    mload(add(transcript, 0x3ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b20),
                addmod(
                    mload(add(transcript, 0x3a60)),
                    sub(f_q, mload(add(transcript, 0x3b00))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b40),
                mulmod(
                    mload(add(transcript, 0x3b20)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b60),
                addmod(
                    mload(add(transcript, 0x39e0)),
                    mload(add(transcript, 0x3b40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b80),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3b60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ba0),
                addmod(
                    mload(add(transcript, 0x1060)),
                    sub(f_q, mload(add(transcript, 0x10a0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3bc0),
                mulmod(
                    mload(add(transcript, 0x3ba0)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3be0),
                addmod(
                    mload(add(transcript, 0x3b80)),
                    mload(add(transcript, 0x3bc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c00),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3be0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c20),
                mulmod(
                    mload(add(transcript, 0x3ba0)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c40),
                addmod(
                    mload(add(transcript, 0x1060)),
                    sub(f_q, mload(add(transcript, 0x1080))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c60),
                mulmod(
                    mload(add(transcript, 0x3c40)),
                    mload(add(transcript, 0x3c20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c80),
                addmod(
                    mload(add(transcript, 0x3c00)),
                    mload(add(transcript, 0x3c60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ca0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3c80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3cc0),
                addmod(1, sub(f_q, mload(add(transcript, 0x10c0))), f_q)
            )
            mstore(
                add(transcript, 0x3ce0),
                mulmod(
                    mload(add(transcript, 0x3cc0)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d00),
                addmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x3ce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d20),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3d00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d40),
                mulmod(
                    mload(add(transcript, 0x10c0)),
                    mload(add(transcript, 0x10c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d60),
                addmod(
                    mload(add(transcript, 0x3d40)),
                    sub(f_q, mload(add(transcript, 0x10c0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d80),
                mulmod(
                    mload(add(transcript, 0x3d60)),
                    mload(add(transcript, 0x2100)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3da0),
                addmod(
                    mload(add(transcript, 0x3d20)),
                    mload(add(transcript, 0x3d80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3dc0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3da0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3de0),
                addmod(
                    mload(add(transcript, 0x1100)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e00),
                mulmod(
                    mload(add(transcript, 0x3de0)),
                    mload(add(transcript, 0x10e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e20),
                addmod(
                    mload(add(transcript, 0x1140)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e40),
                mulmod(
                    mload(add(transcript, 0x3e20)),
                    mload(add(transcript, 0x3e00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e60),
                mulmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e80),
                addmod(
                    mload(add(transcript, 0x3240)),
                    mload(add(transcript, 0x3e60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ea0),
                addmod(
                    mload(add(transcript, 0x3e80)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ec0),
                mulmod(
                    mload(add(transcript, 0x3ea0)),
                    mload(add(transcript, 0x10c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ee0),
                mulmod(
                    mload(add(transcript, 0x3320)),
                    mload(add(transcript, 0x3ec0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f00),
                addmod(
                    mload(add(transcript, 0x3e40)),
                    sub(f_q, mload(add(transcript, 0x3ee0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f20),
                mulmod(
                    mload(add(transcript, 0x3f00)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f40),
                addmod(
                    mload(add(transcript, 0x3dc0)),
                    mload(add(transcript, 0x3f20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f60),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3f40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f80),
                addmod(
                    mload(add(transcript, 0x1100)),
                    sub(f_q, mload(add(transcript, 0x1140))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3fa0),
                mulmod(
                    mload(add(transcript, 0x3f80)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3fc0),
                addmod(
                    mload(add(transcript, 0x3f60)),
                    mload(add(transcript, 0x3fa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3fe0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3fc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4000),
                mulmod(
                    mload(add(transcript, 0x3f80)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4020),
                addmod(
                    mload(add(transcript, 0x1100)),
                    sub(f_q, mload(add(transcript, 0x1120))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4040),
                mulmod(
                    mload(add(transcript, 0x4020)),
                    mload(add(transcript, 0x4000)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4060),
                addmod(
                    mload(add(transcript, 0x3fe0)),
                    mload(add(transcript, 0x4040)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4080),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x4060)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x40a0),
                addmod(1, sub(f_q, mload(add(transcript, 0x1160))), f_q)
            )
            mstore(
                add(transcript, 0x40c0),
                mulmod(
                    mload(add(transcript, 0x40a0)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x40e0),
                addmod(
                    mload(add(transcript, 0x4080)),
                    mload(add(transcript, 0x40c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4100),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x40e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4120),
                mulmod(
                    mload(add(transcript, 0x1160)),
                    mload(add(transcript, 0x1160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4140),
                addmod(
                    mload(add(transcript, 0x4120)),
                    sub(f_q, mload(add(transcript, 0x1160))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4160),
                mulmod(
                    mload(add(transcript, 0x4140)),
                    mload(add(transcript, 0x2100)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4180),
                addmod(
                    mload(add(transcript, 0x4100)),
                    mload(add(transcript, 0x4160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x41a0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x4180)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x41c0),
                addmod(
                    mload(add(transcript, 0x11a0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x41e0),
                mulmod(
                    mload(add(transcript, 0x41c0)),
                    mload(add(transcript, 0x1180)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4200),
                addmod(
                    mload(add(transcript, 0x11e0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4220),
                mulmod(
                    mload(add(transcript, 0x4200)),
                    mload(add(transcript, 0x41e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4240),
                mulmod(
                    mload(add(transcript, 0x3a0)),
                    mload(add(transcript, 0xd00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4260),
                mulmod(
                    mload(add(transcript, 0xae0)),
                    mload(add(transcript, 0xd40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4280),
                addmod(
                    mload(add(transcript, 0x4240)),
                    mload(add(transcript, 0x4260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x42a0),
                addmod(
                    mload(add(transcript, 0x4280)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x42c0),
                mulmod(
                    mload(add(transcript, 0x42a0)),
                    mload(add(transcript, 0x1160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x42e0),
                mulmod(
                    mload(add(transcript, 0x3320)),
                    mload(add(transcript, 0x42c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4300),
                addmod(
                    mload(add(transcript, 0x4220)),
                    sub(f_q, mload(add(transcript, 0x42e0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4320),
                mulmod(
                    mload(add(transcript, 0x4300)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4340),
                addmod(
                    mload(add(transcript, 0x41a0)),
                    mload(add(transcript, 0x4320)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4360),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x4340)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4380),
                addmod(
                    mload(add(transcript, 0x11a0)),
                    sub(f_q, mload(add(transcript, 0x11e0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x43a0),
                mulmod(
                    mload(add(transcript, 0x4380)),
                    mload(add(transcript, 0x21c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x43c0),
                addmod(
                    mload(add(transcript, 0x4360)),
                    mload(add(transcript, 0x43a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x43e0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x43c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4400),
                mulmod(
                    mload(add(transcript, 0x4380)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4420),
                addmod(
                    mload(add(transcript, 0x11a0)),
                    sub(f_q, mload(add(transcript, 0x11c0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4440),
                mulmod(
                    mload(add(transcript, 0x4420)),
                    mload(add(transcript, 0x4400)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4460),
                addmod(
                    mload(add(transcript, 0x43e0)),
                    mload(add(transcript, 0x4440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4480),
                mulmod(
                    mload(add(transcript, 0x1720)),
                    mload(add(transcript, 0x1720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x44a0),
                mulmod(
                    mload(add(transcript, 0x4480)),
                    mload(add(transcript, 0x1720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x44c0),
                mulmod(
                    mload(add(transcript, 0x44a0)),
                    mload(add(transcript, 0x1720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x44e0),
                mulmod(1, mload(add(transcript, 0x1720)), f_q)
            )
            mstore(
                add(transcript, 0x4500),
                mulmod(1, mload(add(transcript, 0x4480)), f_q)
            )
            mstore(
                add(transcript, 0x4520),
                mulmod(1, mload(add(transcript, 0x44a0)), f_q)
            )
            mstore(
                add(transcript, 0x4540),
                mulmod(
                    mload(add(transcript, 0x4460)),
                    mload(add(transcript, 0x1740)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4560),
                mulmod(
                    mload(add(transcript, 0x1380)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4580),
                mulmod(
                    mload(add(transcript, 0x4560)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x45a0),
                mulmod(
                    mload(add(transcript, 0x4580)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x45c0),
                mulmod(
                    mload(add(transcript, 0x1220)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x45e0),
                mulmod(
                    mload(add(transcript, 0x45c0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4600),
                mulmod(
                    mload(add(transcript, 0x45e0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4620),
                mulmod(
                    mload(add(transcript, 0x4600)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4640),
                mulmod(
                    mload(add(transcript, 0x4620)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4660),
                mulmod(
                    mload(add(transcript, 0x4640)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4680),
                mulmod(
                    mload(add(transcript, 0x4660)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x46a0),
                mulmod(
                    mload(add(transcript, 0x4680)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x46c0),
                mulmod(
                    mload(add(transcript, 0x46a0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x46e0),
                mulmod(
                    mload(add(transcript, 0x46c0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4700),
                mulmod(
                    mload(add(transcript, 0x46e0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4720),
                mulmod(
                    mload(add(transcript, 0x4700)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4740),
                mulmod(
                    mload(add(transcript, 0x4720)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4760),
                mulmod(
                    mload(add(transcript, 0x4740)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4780),
                mulmod(
                    mload(add(transcript, 0x4760)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x47a0),
                mulmod(
                    mload(add(transcript, 0x4780)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x47c0),
                mulmod(
                    mload(add(transcript, 0x47a0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x47e0),
                mulmod(
                    mload(add(transcript, 0x47c0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4800),
                mulmod(
                    mload(add(transcript, 0x47e0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4820),
                mulmod(
                    mload(add(transcript, 0x4800)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4840),
                mulmod(
                    mload(add(transcript, 0x4820)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4860),
                mulmod(
                    mload(add(transcript, 0x4840)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4880),
                mulmod(
                    mload(add(transcript, 0x4860)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x48a0),
                mulmod(
                    mload(add(transcript, 0x4880)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x48c0),
                mulmod(
                    mload(add(transcript, 0x48a0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x48e0),
                mulmod(
                    mload(add(transcript, 0x48c0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4900),
                mulmod(
                    mload(add(transcript, 0x48e0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4920),
                mulmod(
                    mload(add(transcript, 0x4900)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4940),
                mulmod(
                    mload(add(transcript, 0x4920)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4960),
                mulmod(
                    mload(add(transcript, 0x4940)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4980),
                mulmod(
                    mload(add(transcript, 0x4960)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x49a0),
                mulmod(
                    mload(add(transcript, 0x4980)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x49c0),
                mulmod(
                    mload(add(transcript, 0x49a0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x49e0),
                mulmod(
                    mload(add(transcript, 0x49c0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4a00),
                mulmod(
                    mload(add(transcript, 0x49e0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4a20),
                mulmod(
                    mload(add(transcript, 0x4a00)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4a40),
                mulmod(
                    mload(add(transcript, 0x4a20)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4a60),
                mulmod(
                    mload(add(transcript, 0x4a40)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4a80),
                mulmod(
                    mload(add(transcript, 0x4a60)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4aa0),
                mulmod(
                    mload(add(transcript, 0x4a80)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ac0),
                mulmod(
                    mload(add(transcript, 0x4aa0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ae0),
                mulmod(
                    mload(add(transcript, 0x4ac0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4b00),
                mulmod(
                    mload(add(transcript, 0x4ae0)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4b20),
                mulmod(sub(f_q, mload(add(transcript, 0xae0))), 1, f_q)
            )
            mstore(
                add(transcript, 0x4b40),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xb00))),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4b60),
                mulmod(1, mload(add(transcript, 0x1220)), f_q)
            )
            mstore(
                add(transcript, 0x4b80),
                addmod(
                    mload(add(transcript, 0x4b20)),
                    mload(add(transcript, 0x4b40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ba0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xb20))),
                    mload(add(transcript, 0x45c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4bc0),
                mulmod(1, mload(add(transcript, 0x45c0)), f_q)
            )
            mstore(
                add(transcript, 0x4be0),
                addmod(
                    mload(add(transcript, 0x4b80)),
                    mload(add(transcript, 0x4ba0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4c00),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xb40))),
                    mload(add(transcript, 0x45e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4c20),
                mulmod(1, mload(add(transcript, 0x45e0)), f_q)
            )
            mstore(
                add(transcript, 0x4c40),
                addmod(
                    mload(add(transcript, 0x4be0)),
                    mload(add(transcript, 0x4c00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4c60),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xb60))),
                    mload(add(transcript, 0x4600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4c80),
                mulmod(1, mload(add(transcript, 0x4600)), f_q)
            )
            mstore(
                add(transcript, 0x4ca0),
                addmod(
                    mload(add(transcript, 0x4c40)),
                    mload(add(transcript, 0x4c60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4cc0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xe40))),
                    mload(add(transcript, 0x4620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ce0),
                mulmod(1, mload(add(transcript, 0x4620)), f_q)
            )
            mstore(
                add(transcript, 0x4d00),
                addmod(
                    mload(add(transcript, 0x4ca0)),
                    mload(add(transcript, 0x4cc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4d20),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xea0))),
                    mload(add(transcript, 0x4640)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4d40),
                mulmod(1, mload(add(transcript, 0x4640)), f_q)
            )
            mstore(
                add(transcript, 0x4d60),
                addmod(
                    mload(add(transcript, 0x4d00)),
                    mload(add(transcript, 0x4d20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4d80),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xee0))),
                    mload(add(transcript, 0x4660)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4da0),
                mulmod(1, mload(add(transcript, 0x4660)), f_q)
            )
            mstore(
                add(transcript, 0x4dc0),
                addmod(
                    mload(add(transcript, 0x4d60)),
                    mload(add(transcript, 0x4d80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4de0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xf20))),
                    mload(add(transcript, 0x4680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4e00),
                mulmod(1, mload(add(transcript, 0x4680)), f_q)
            )
            mstore(
                add(transcript, 0x4e20),
                addmod(
                    mload(add(transcript, 0x4dc0)),
                    mload(add(transcript, 0x4de0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4e40),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xf60))),
                    mload(add(transcript, 0x46a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4e60),
                mulmod(1, mload(add(transcript, 0x46a0)), f_q)
            )
            mstore(
                add(transcript, 0x4e80),
                addmod(
                    mload(add(transcript, 0x4e20)),
                    mload(add(transcript, 0x4e40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ea0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xf80))),
                    mload(add(transcript, 0x46c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ec0),
                mulmod(1, mload(add(transcript, 0x46c0)), f_q)
            )
            mstore(
                add(transcript, 0x4ee0),
                addmod(
                    mload(add(transcript, 0x4e80)),
                    mload(add(transcript, 0x4ea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4f00),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xfc0))),
                    mload(add(transcript, 0x46e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4f20),
                mulmod(1, mload(add(transcript, 0x46e0)), f_q)
            )
            mstore(
                add(transcript, 0x4f40),
                addmod(
                    mload(add(transcript, 0x4ee0)),
                    mload(add(transcript, 0x4f00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4f60),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1000))),
                    mload(add(transcript, 0x4700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4f80),
                mulmod(1, mload(add(transcript, 0x4700)), f_q)
            )
            mstore(
                add(transcript, 0x4fa0),
                addmod(
                    mload(add(transcript, 0x4f40)),
                    mload(add(transcript, 0x4f60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4fc0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1020))),
                    mload(add(transcript, 0x4720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4fe0),
                mulmod(1, mload(add(transcript, 0x4720)), f_q)
            )
            mstore(
                add(transcript, 0x5000),
                addmod(
                    mload(add(transcript, 0x4fa0)),
                    mload(add(transcript, 0x4fc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5020),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1060))),
                    mload(add(transcript, 0x4740)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5040),
                mulmod(1, mload(add(transcript, 0x4740)), f_q)
            )
            mstore(
                add(transcript, 0x5060),
                addmod(
                    mload(add(transcript, 0x5000)),
                    mload(add(transcript, 0x5020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5080),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x10a0))),
                    mload(add(transcript, 0x4760)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x50a0),
                mulmod(1, mload(add(transcript, 0x4760)), f_q)
            )
            mstore(
                add(transcript, 0x50c0),
                addmod(
                    mload(add(transcript, 0x5060)),
                    mload(add(transcript, 0x5080)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x50e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x10c0))),
                    mload(add(transcript, 0x4780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5100),
                mulmod(1, mload(add(transcript, 0x4780)), f_q)
            )
            mstore(
                add(transcript, 0x5120),
                addmod(
                    mload(add(transcript, 0x50c0)),
                    mload(add(transcript, 0x50e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5140),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1100))),
                    mload(add(transcript, 0x47a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5160),
                mulmod(1, mload(add(transcript, 0x47a0)), f_q)
            )
            mstore(
                add(transcript, 0x5180),
                addmod(
                    mload(add(transcript, 0x5120)),
                    mload(add(transcript, 0x5140)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x51a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1140))),
                    mload(add(transcript, 0x47c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x51c0),
                mulmod(1, mload(add(transcript, 0x47c0)), f_q)
            )
            mstore(
                add(transcript, 0x51e0),
                addmod(
                    mload(add(transcript, 0x5180)),
                    mload(add(transcript, 0x51a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5200),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1160))),
                    mload(add(transcript, 0x47e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5220),
                mulmod(1, mload(add(transcript, 0x47e0)), f_q)
            )
            mstore(
                add(transcript, 0x5240),
                addmod(
                    mload(add(transcript, 0x51e0)),
                    mload(add(transcript, 0x5200)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5260),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x11a0))),
                    mload(add(transcript, 0x4800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5280),
                mulmod(1, mload(add(transcript, 0x4800)), f_q)
            )
            mstore(
                add(transcript, 0x52a0),
                addmod(
                    mload(add(transcript, 0x5240)),
                    mload(add(transcript, 0x5260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x52c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x11e0))),
                    mload(add(transcript, 0x4820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x52e0),
                mulmod(1, mload(add(transcript, 0x4820)), f_q)
            )
            mstore(
                add(transcript, 0x5300),
                addmod(
                    mload(add(transcript, 0x52a0)),
                    mload(add(transcript, 0x52c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5320),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xba0))),
                    mload(add(transcript, 0x4840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5340),
                mulmod(1, mload(add(transcript, 0x4840)), f_q)
            )
            mstore(
                add(transcript, 0x5360),
                addmod(
                    mload(add(transcript, 0x5300)),
                    mload(add(transcript, 0x5320)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5380),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xbc0))),
                    mload(add(transcript, 0x4860)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x53a0),
                mulmod(1, mload(add(transcript, 0x4860)), f_q)
            )
            mstore(
                add(transcript, 0x53c0),
                addmod(
                    mload(add(transcript, 0x5360)),
                    mload(add(transcript, 0x5380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x53e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xbe0))),
                    mload(add(transcript, 0x4880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5400),
                mulmod(1, mload(add(transcript, 0x4880)), f_q)
            )
            mstore(
                add(transcript, 0x5420),
                addmod(
                    mload(add(transcript, 0x53c0)),
                    mload(add(transcript, 0x53e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5440),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xc00))),
                    mload(add(transcript, 0x48a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5460),
                mulmod(1, mload(add(transcript, 0x48a0)), f_q)
            )
            mstore(
                add(transcript, 0x5480),
                addmod(
                    mload(add(transcript, 0x5420)),
                    mload(add(transcript, 0x5440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x54a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xc20))),
                    mload(add(transcript, 0x48c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x54c0),
                mulmod(1, mload(add(transcript, 0x48c0)), f_q)
            )
            mstore(
                add(transcript, 0x54e0),
                addmod(
                    mload(add(transcript, 0x5480)),
                    mload(add(transcript, 0x54a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5500),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xc40))),
                    mload(add(transcript, 0x48e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5520),
                mulmod(1, mload(add(transcript, 0x48e0)), f_q)
            )
            mstore(
                add(transcript, 0x5540),
                addmod(
                    mload(add(transcript, 0x54e0)),
                    mload(add(transcript, 0x5500)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5560),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xc60))),
                    mload(add(transcript, 0x4900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5580),
                mulmod(1, mload(add(transcript, 0x4900)), f_q)
            )
            mstore(
                add(transcript, 0x55a0),
                addmod(
                    mload(add(transcript, 0x5540)),
                    mload(add(transcript, 0x5560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x55c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xc80))),
                    mload(add(transcript, 0x4920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x55e0),
                mulmod(1, mload(add(transcript, 0x4920)), f_q)
            )
            mstore(
                add(transcript, 0x5600),
                addmod(
                    mload(add(transcript, 0x55a0)),
                    mload(add(transcript, 0x55c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5620),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xca0))),
                    mload(add(transcript, 0x4940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5640),
                mulmod(1, mload(add(transcript, 0x4940)), f_q)
            )
            mstore(
                add(transcript, 0x5660),
                addmod(
                    mload(add(transcript, 0x5600)),
                    mload(add(transcript, 0x5620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5680),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xcc0))),
                    mload(add(transcript, 0x4960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x56a0),
                mulmod(1, mload(add(transcript, 0x4960)), f_q)
            )
            mstore(
                add(transcript, 0x56c0),
                addmod(
                    mload(add(transcript, 0x5660)),
                    mload(add(transcript, 0x5680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x56e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xce0))),
                    mload(add(transcript, 0x4980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5700),
                mulmod(1, mload(add(transcript, 0x4980)), f_q)
            )
            mstore(
                add(transcript, 0x5720),
                addmod(
                    mload(add(transcript, 0x56c0)),
                    mload(add(transcript, 0x56e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5740),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xd00))),
                    mload(add(transcript, 0x49a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5760),
                mulmod(1, mload(add(transcript, 0x49a0)), f_q)
            )
            mstore(
                add(transcript, 0x5780),
                addmod(
                    mload(add(transcript, 0x5720)),
                    mload(add(transcript, 0x5740)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x57a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xd20))),
                    mload(add(transcript, 0x49c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x57c0),
                mulmod(1, mload(add(transcript, 0x49c0)), f_q)
            )
            mstore(
                add(transcript, 0x57e0),
                addmod(
                    mload(add(transcript, 0x5780)),
                    mload(add(transcript, 0x57a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5800),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xd40))),
                    mload(add(transcript, 0x49e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5820),
                mulmod(1, mload(add(transcript, 0x49e0)), f_q)
            )
            mstore(
                add(transcript, 0x5840),
                addmod(
                    mload(add(transcript, 0x57e0)),
                    mload(add(transcript, 0x5800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5860),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xd80))),
                    mload(add(transcript, 0x4a00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5880),
                mulmod(1, mload(add(transcript, 0x4a00)), f_q)
            )
            mstore(
                add(transcript, 0x58a0),
                addmod(
                    mload(add(transcript, 0x5840)),
                    mload(add(transcript, 0x5860)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x58c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xda0))),
                    mload(add(transcript, 0x4a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x58e0),
                mulmod(1, mload(add(transcript, 0x4a20)), f_q)
            )
            mstore(
                add(transcript, 0x5900),
                addmod(
                    mload(add(transcript, 0x58a0)),
                    mload(add(transcript, 0x58c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5920),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xdc0))),
                    mload(add(transcript, 0x4a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5940),
                mulmod(1, mload(add(transcript, 0x4a40)), f_q)
            )
            mstore(
                add(transcript, 0x5960),
                addmod(
                    mload(add(transcript, 0x5900)),
                    mload(add(transcript, 0x5920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5980),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xde0))),
                    mload(add(transcript, 0x4a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x59a0),
                mulmod(1, mload(add(transcript, 0x4a60)), f_q)
            )
            mstore(
                add(transcript, 0x59c0),
                addmod(
                    mload(add(transcript, 0x5960)),
                    mload(add(transcript, 0x5980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x59e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xe00))),
                    mload(add(transcript, 0x4a80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5a00),
                mulmod(1, mload(add(transcript, 0x4a80)), f_q)
            )
            mstore(
                add(transcript, 0x5a20),
                addmod(
                    mload(add(transcript, 0x59c0)),
                    mload(add(transcript, 0x59e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5a40),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xe20))),
                    mload(add(transcript, 0x4aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5a60),
                mulmod(1, mload(add(transcript, 0x4aa0)), f_q)
            )
            mstore(
                add(transcript, 0x5a80),
                addmod(
                    mload(add(transcript, 0x5a20)),
                    mload(add(transcript, 0x5a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5aa0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x4540))),
                    mload(add(transcript, 0x4ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5ac0),
                mulmod(1, mload(add(transcript, 0x4ac0)), f_q)
            )
            mstore(
                add(transcript, 0x5ae0),
                mulmod(
                    mload(add(transcript, 0x44e0)),
                    mload(add(transcript, 0x4ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5b00),
                mulmod(
                    mload(add(transcript, 0x4500)),
                    mload(add(transcript, 0x4ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5b20),
                mulmod(
                    mload(add(transcript, 0x4520)),
                    mload(add(transcript, 0x4ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5b40),
                addmod(
                    mload(add(transcript, 0x5a80)),
                    mload(add(transcript, 0x5aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5b60),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xd60))),
                    mload(add(transcript, 0x4ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5b80),
                mulmod(1, mload(add(transcript, 0x4ae0)), f_q)
            )
            mstore(
                add(transcript, 0x5ba0),
                addmod(
                    mload(add(transcript, 0x5b40)),
                    mload(add(transcript, 0x5b60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5bc0),
                mulmod(mload(add(transcript, 0x5ba0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5be0),
                mulmod(mload(add(transcript, 0x4b60)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5c00),
                mulmod(mload(add(transcript, 0x4bc0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5c20),
                mulmod(mload(add(transcript, 0x4c20)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5c40),
                mulmod(mload(add(transcript, 0x4c80)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5c60),
                mulmod(mload(add(transcript, 0x4ce0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5c80),
                mulmod(mload(add(transcript, 0x4d40)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5ca0),
                mulmod(mload(add(transcript, 0x4da0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5cc0),
                mulmod(mload(add(transcript, 0x4e00)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5ce0),
                mulmod(mload(add(transcript, 0x4e60)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5d00),
                mulmod(mload(add(transcript, 0x4ec0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5d20),
                mulmod(mload(add(transcript, 0x4f20)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5d40),
                mulmod(mload(add(transcript, 0x4f80)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5d60),
                mulmod(mload(add(transcript, 0x4fe0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5d80),
                mulmod(mload(add(transcript, 0x5040)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5da0),
                mulmod(mload(add(transcript, 0x50a0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5dc0),
                mulmod(mload(add(transcript, 0x5100)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5de0),
                mulmod(mload(add(transcript, 0x5160)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5e00),
                mulmod(mload(add(transcript, 0x51c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5e20),
                mulmod(mload(add(transcript, 0x5220)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5e40),
                mulmod(mload(add(transcript, 0x5280)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5e60),
                mulmod(mload(add(transcript, 0x52e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5e80),
                mulmod(mload(add(transcript, 0x5340)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5ea0),
                mulmod(mload(add(transcript, 0x53a0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5ec0),
                mulmod(mload(add(transcript, 0x5400)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5ee0),
                mulmod(mload(add(transcript, 0x5460)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5f00),
                mulmod(mload(add(transcript, 0x54c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5f20),
                mulmod(mload(add(transcript, 0x5520)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5f40),
                mulmod(mload(add(transcript, 0x5580)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5f60),
                mulmod(mload(add(transcript, 0x55e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5f80),
                mulmod(mload(add(transcript, 0x5640)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5fa0),
                mulmod(mload(add(transcript, 0x56a0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5fc0),
                mulmod(mload(add(transcript, 0x5700)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5fe0),
                mulmod(mload(add(transcript, 0x5760)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6000),
                mulmod(mload(add(transcript, 0x57c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6020),
                mulmod(mload(add(transcript, 0x5820)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6040),
                mulmod(mload(add(transcript, 0x5880)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6060),
                mulmod(mload(add(transcript, 0x58e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6080),
                mulmod(mload(add(transcript, 0x5940)), 1, f_q)
            )
            mstore(
                add(transcript, 0x60a0),
                mulmod(mload(add(transcript, 0x59a0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x60c0),
                mulmod(mload(add(transcript, 0x5a00)), 1, f_q)
            )
            mstore(
                add(transcript, 0x60e0),
                mulmod(mload(add(transcript, 0x5a60)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6100),
                mulmod(mload(add(transcript, 0x5ac0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6120),
                mulmod(mload(add(transcript, 0x5ae0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6140),
                mulmod(mload(add(transcript, 0x5b00)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6160),
                mulmod(mload(add(transcript, 0x5b20)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6180),
                mulmod(mload(add(transcript, 0x5b80)), 1, f_q)
            )
            mstore(
                add(transcript, 0x61a0),
                mulmod(sub(f_q, mload(add(transcript, 0xb80))), 1, f_q)
            )
            mstore(
                add(transcript, 0x61c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xe60))),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x61e0),
                addmod(
                    mload(add(transcript, 0x61a0)),
                    mload(add(transcript, 0x61c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6200),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xec0))),
                    mload(add(transcript, 0x45c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6220),
                addmod(
                    mload(add(transcript, 0x61e0)),
                    mload(add(transcript, 0x6200)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6240),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xf00))),
                    mload(add(transcript, 0x45e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6260),
                addmod(
                    mload(add(transcript, 0x6220)),
                    mload(add(transcript, 0x6240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6280),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xfa0))),
                    mload(add(transcript, 0x4600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x62a0),
                addmod(
                    mload(add(transcript, 0x6260)),
                    mload(add(transcript, 0x6280)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x62c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1040))),
                    mload(add(transcript, 0x4620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x62e0),
                addmod(
                    mload(add(transcript, 0x62a0)),
                    mload(add(transcript, 0x62c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6300),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x10e0))),
                    mload(add(transcript, 0x4640)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6320),
                addmod(
                    mload(add(transcript, 0x62e0)),
                    mload(add(transcript, 0x6300)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6340),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1180))),
                    mload(add(transcript, 0x4660)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6360),
                addmod(
                    mload(add(transcript, 0x6320)),
                    mload(add(transcript, 0x6340)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6380),
                mulmod(
                    mload(add(transcript, 0x6360)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x63a0),
                mulmod(1, mload(add(transcript, 0x1380)), f_q)
            )
            mstore(
                add(transcript, 0x63c0),
                mulmod(
                    mload(add(transcript, 0x4b60)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x63e0),
                mulmod(
                    mload(add(transcript, 0x4bc0)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6400),
                mulmod(
                    mload(add(transcript, 0x4c20)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6420),
                mulmod(
                    mload(add(transcript, 0x4c80)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6440),
                mulmod(
                    mload(add(transcript, 0x4ce0)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6460),
                mulmod(
                    mload(add(transcript, 0x4d40)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6480),
                mulmod(
                    mload(add(transcript, 0x4da0)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x64a0),
                addmod(
                    mload(add(transcript, 0x5bc0)),
                    mload(add(transcript, 0x6380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x64c0),
                addmod(
                    mload(add(transcript, 0x5c40)),
                    mload(add(transcript, 0x63a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x64e0),
                addmod(
                    mload(add(transcript, 0x5c60)),
                    mload(add(transcript, 0x63c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6500),
                addmod(
                    mload(add(transcript, 0x5c80)),
                    mload(add(transcript, 0x63e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6520),
                addmod(
                    mload(add(transcript, 0x5ca0)),
                    mload(add(transcript, 0x6400)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6540),
                addmod(
                    mload(add(transcript, 0x5d00)),
                    mload(add(transcript, 0x6420)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6560),
                addmod(
                    mload(add(transcript, 0x5d60)),
                    mload(add(transcript, 0x6440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6580),
                addmod(
                    mload(add(transcript, 0x5dc0)),
                    mload(add(transcript, 0x6460)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x65a0),
                addmod(
                    mload(add(transcript, 0x5e20)),
                    mload(add(transcript, 0x6480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x65c0),
                mulmod(sub(f_q, mload(add(transcript, 0xe80))), 1, f_q)
            )
            mstore(
                add(transcript, 0x65e0),
                mulmod(
                    mload(add(transcript, 0x65c0)),
                    mload(add(transcript, 0x4560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6600),
                mulmod(1, mload(add(transcript, 0x4560)), f_q)
            )
            mstore(
                add(transcript, 0x6620),
                addmod(
                    mload(add(transcript, 0x64a0)),
                    mload(add(transcript, 0x65e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6640),
                addmod(
                    mload(add(transcript, 0x64e0)),
                    mload(add(transcript, 0x6600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6660),
                mulmod(sub(f_q, mload(add(transcript, 0xf40))), 1, f_q)
            )
            mstore(
                add(transcript, 0x6680),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xfe0))),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x66a0),
                addmod(
                    mload(add(transcript, 0x6660)),
                    mload(add(transcript, 0x6680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x66c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1080))),
                    mload(add(transcript, 0x45c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x66e0),
                addmod(
                    mload(add(transcript, 0x66a0)),
                    mload(add(transcript, 0x66c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6700),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1120))),
                    mload(add(transcript, 0x45e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6720),
                addmod(
                    mload(add(transcript, 0x66e0)),
                    mload(add(transcript, 0x6700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6740),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x11c0))),
                    mload(add(transcript, 0x4600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6760),
                addmod(
                    mload(add(transcript, 0x6720)),
                    mload(add(transcript, 0x6740)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6780),
                mulmod(
                    mload(add(transcript, 0x6760)),
                    mload(add(transcript, 0x4580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x67a0),
                mulmod(1, mload(add(transcript, 0x4580)), f_q)
            )
            mstore(
                add(transcript, 0x67c0),
                mulmod(
                    mload(add(transcript, 0x4b60)),
                    mload(add(transcript, 0x4580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x67e0),
                mulmod(
                    mload(add(transcript, 0x4bc0)),
                    mload(add(transcript, 0x4580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6800),
                mulmod(
                    mload(add(transcript, 0x4c20)),
                    mload(add(transcript, 0x4580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6820),
                mulmod(
                    mload(add(transcript, 0x4c80)),
                    mload(add(transcript, 0x4580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6840),
                addmod(
                    mload(add(transcript, 0x6620)),
                    mload(add(transcript, 0x6780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6860),
                addmod(
                    mload(add(transcript, 0x5cc0)),
                    mload(add(transcript, 0x67a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6880),
                addmod(
                    mload(add(transcript, 0x5d20)),
                    mload(add(transcript, 0x67c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x68a0),
                addmod(
                    mload(add(transcript, 0x5d80)),
                    mload(add(transcript, 0x67e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x68c0),
                addmod(
                    mload(add(transcript, 0x5de0)),
                    mload(add(transcript, 0x6800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x68e0),
                addmod(
                    mload(add(transcript, 0x5e40)),
                    mload(add(transcript, 0x6820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6900),
                mulmod(1, mload(add(transcript, 0xaa0)), f_q)
            )
            mstore(
                add(transcript, 0x6920),
                mulmod(1, mload(add(transcript, 0x6900)), f_q)
            )
            mstore(
                add(transcript, 0x6940),
                mulmod(
                    11451405578697956743456240853980216273390554734748796433026540431386972584651,
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6960),
                mulmod(
                    mload(add(transcript, 0x63a0)),
                    mload(add(transcript, 0x6940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6980),
                mulmod(
                    14655294445420895451632927078981340937842238432098198055057679026789553137428,
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x69a0),
                mulmod(
                    mload(add(transcript, 0x6600)),
                    mload(add(transcript, 0x6980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x69c0),
                mulmod(
                    17329448237240114492580865744088056414251735686965494637158808787419781175510,
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x69e0),
                mulmod(
                    mload(add(transcript, 0x67a0)),
                    mload(add(transcript, 0x69c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6a00),
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            mstore(
                add(transcript, 0x6a20),
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            mstore(add(transcript, 0x6a40), mload(add(transcript, 0x6840)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6a00),
                        0x60,
                        add(transcript, 0x6a00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6a60), mload(add(transcript, 0x6a00)))
            mstore(add(transcript, 0x6a80), mload(add(transcript, 0x6a20)))
            mstore(add(transcript, 0x6aa0), mload(add(transcript, 0x240)))
            mstore(add(transcript, 0x6ac0), mload(add(transcript, 0x260)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6a60),
                        0x80,
                        add(transcript, 0x6a60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6ae0), mload(add(transcript, 0x280)))
            mstore(add(transcript, 0x6b00), mload(add(transcript, 0x2a0)))
            mstore(add(transcript, 0x6b20), mload(add(transcript, 0x5be0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6ae0),
                        0x60,
                        add(transcript, 0x6ae0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6b40), mload(add(transcript, 0x6a60)))
            mstore(add(transcript, 0x6b60), mload(add(transcript, 0x6a80)))
            mstore(add(transcript, 0x6b80), mload(add(transcript, 0x6ae0)))
            mstore(add(transcript, 0x6ba0), mload(add(transcript, 0x6b00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6b40),
                        0x80,
                        add(transcript, 0x6b40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6bc0), mload(add(transcript, 0x2c0)))
            mstore(add(transcript, 0x6be0), mload(add(transcript, 0x2e0)))
            mstore(add(transcript, 0x6c00), mload(add(transcript, 0x5c00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6bc0),
                        0x60,
                        add(transcript, 0x6bc0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6c20), mload(add(transcript, 0x6b40)))
            mstore(add(transcript, 0x6c40), mload(add(transcript, 0x6b60)))
            mstore(add(transcript, 0x6c60), mload(add(transcript, 0x6bc0)))
            mstore(add(transcript, 0x6c80), mload(add(transcript, 0x6be0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6c20),
                        0x80,
                        add(transcript, 0x6c20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6ca0), mload(add(transcript, 0x300)))
            mstore(add(transcript, 0x6cc0), mload(add(transcript, 0x320)))
            mstore(add(transcript, 0x6ce0), mload(add(transcript, 0x5c20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6ca0),
                        0x60,
                        add(transcript, 0x6ca0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6d00), mload(add(transcript, 0x6c20)))
            mstore(add(transcript, 0x6d20), mload(add(transcript, 0x6c40)))
            mstore(add(transcript, 0x6d40), mload(add(transcript, 0x6ca0)))
            mstore(add(transcript, 0x6d60), mload(add(transcript, 0x6cc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6d00),
                        0x80,
                        add(transcript, 0x6d00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6d80), mload(add(transcript, 0x340)))
            mstore(add(transcript, 0x6da0), mload(add(transcript, 0x360)))
            mstore(add(transcript, 0x6dc0), mload(add(transcript, 0x64c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6d80),
                        0x60,
                        add(transcript, 0x6d80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6de0), mload(add(transcript, 0x6d00)))
            mstore(add(transcript, 0x6e00), mload(add(transcript, 0x6d20)))
            mstore(add(transcript, 0x6e20), mload(add(transcript, 0x6d80)))
            mstore(add(transcript, 0x6e40), mload(add(transcript, 0x6da0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6de0),
                        0x80,
                        add(transcript, 0x6de0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6e60), mload(add(transcript, 0x720)))
            mstore(add(transcript, 0x6e80), mload(add(transcript, 0x740)))
            mstore(add(transcript, 0x6ea0), mload(add(transcript, 0x6640)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6e60),
                        0x60,
                        add(transcript, 0x6e60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6ec0), mload(add(transcript, 0x6de0)))
            mstore(add(transcript, 0x6ee0), mload(add(transcript, 0x6e00)))
            mstore(add(transcript, 0x6f00), mload(add(transcript, 0x6e60)))
            mstore(add(transcript, 0x6f20), mload(add(transcript, 0x6e80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6ec0),
                        0x80,
                        add(transcript, 0x6ec0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6f40), mload(add(transcript, 0x760)))
            mstore(add(transcript, 0x6f60), mload(add(transcript, 0x780)))
            mstore(add(transcript, 0x6f80), mload(add(transcript, 0x6500)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6f40),
                        0x60,
                        add(transcript, 0x6f40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6fa0), mload(add(transcript, 0x6ec0)))
            mstore(add(transcript, 0x6fc0), mload(add(transcript, 0x6ee0)))
            mstore(add(transcript, 0x6fe0), mload(add(transcript, 0x6f40)))
            mstore(add(transcript, 0x7000), mload(add(transcript, 0x6f60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6fa0),
                        0x80,
                        add(transcript, 0x6fa0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7020), mload(add(transcript, 0x7a0)))
            mstore(add(transcript, 0x7040), mload(add(transcript, 0x7c0)))
            mstore(add(transcript, 0x7060), mload(add(transcript, 0x6520)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7020),
                        0x60,
                        add(transcript, 0x7020),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7080), mload(add(transcript, 0x6fa0)))
            mstore(add(transcript, 0x70a0), mload(add(transcript, 0x6fc0)))
            mstore(add(transcript, 0x70c0), mload(add(transcript, 0x7020)))
            mstore(add(transcript, 0x70e0), mload(add(transcript, 0x7040)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7080),
                        0x80,
                        add(transcript, 0x7080),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7100), mload(add(transcript, 0x3e0)))
            mstore(add(transcript, 0x7120), mload(add(transcript, 0x400)))
            mstore(add(transcript, 0x7140), mload(add(transcript, 0x6860)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7100),
                        0x60,
                        add(transcript, 0x7100),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7160), mload(add(transcript, 0x7080)))
            mstore(add(transcript, 0x7180), mload(add(transcript, 0x70a0)))
            mstore(add(transcript, 0x71a0), mload(add(transcript, 0x7100)))
            mstore(add(transcript, 0x71c0), mload(add(transcript, 0x7120)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7160),
                        0x80,
                        add(transcript, 0x7160),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x71e0), mload(add(transcript, 0x420)))
            mstore(add(transcript, 0x7200), mload(add(transcript, 0x440)))
            mstore(add(transcript, 0x7220), mload(add(transcript, 0x5ce0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x71e0),
                        0x60,
                        add(transcript, 0x71e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7240), mload(add(transcript, 0x7160)))
            mstore(add(transcript, 0x7260), mload(add(transcript, 0x7180)))
            mstore(add(transcript, 0x7280), mload(add(transcript, 0x71e0)))
            mstore(add(transcript, 0x72a0), mload(add(transcript, 0x7200)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7240),
                        0x80,
                        add(transcript, 0x7240),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x72c0), mload(add(transcript, 0x7e0)))
            mstore(add(transcript, 0x72e0), mload(add(transcript, 0x800)))
            mstore(add(transcript, 0x7300), mload(add(transcript, 0x6540)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x72c0),
                        0x60,
                        add(transcript, 0x72c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7320), mload(add(transcript, 0x7240)))
            mstore(add(transcript, 0x7340), mload(add(transcript, 0x7260)))
            mstore(add(transcript, 0x7360), mload(add(transcript, 0x72c0)))
            mstore(add(transcript, 0x7380), mload(add(transcript, 0x72e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7320),
                        0x80,
                        add(transcript, 0x7320),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x73a0), mload(add(transcript, 0x460)))
            mstore(add(transcript, 0x73c0), mload(add(transcript, 0x480)))
            mstore(add(transcript, 0x73e0), mload(add(transcript, 0x6880)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x73a0),
                        0x60,
                        add(transcript, 0x73a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7400), mload(add(transcript, 0x7320)))
            mstore(add(transcript, 0x7420), mload(add(transcript, 0x7340)))
            mstore(add(transcript, 0x7440), mload(add(transcript, 0x73a0)))
            mstore(add(transcript, 0x7460), mload(add(transcript, 0x73c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7400),
                        0x80,
                        add(transcript, 0x7400),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7480), mload(add(transcript, 0x4a0)))
            mstore(add(transcript, 0x74a0), mload(add(transcript, 0x4c0)))
            mstore(add(transcript, 0x74c0), mload(add(transcript, 0x5d40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7480),
                        0x60,
                        add(transcript, 0x7480),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x74e0), mload(add(transcript, 0x7400)))
            mstore(add(transcript, 0x7500), mload(add(transcript, 0x7420)))
            mstore(add(transcript, 0x7520), mload(add(transcript, 0x7480)))
            mstore(add(transcript, 0x7540), mload(add(transcript, 0x74a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x74e0),
                        0x80,
                        add(transcript, 0x74e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7560), mload(add(transcript, 0x820)))
            mstore(add(transcript, 0x7580), mload(add(transcript, 0x840)))
            mstore(add(transcript, 0x75a0), mload(add(transcript, 0x6560)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7560),
                        0x60,
                        add(transcript, 0x7560),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x75c0), mload(add(transcript, 0x74e0)))
            mstore(add(transcript, 0x75e0), mload(add(transcript, 0x7500)))
            mstore(add(transcript, 0x7600), mload(add(transcript, 0x7560)))
            mstore(add(transcript, 0x7620), mload(add(transcript, 0x7580)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x75c0),
                        0x80,
                        add(transcript, 0x75c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7640), mload(add(transcript, 0x4e0)))
            mstore(add(transcript, 0x7660), mload(add(transcript, 0x500)))
            mstore(add(transcript, 0x7680), mload(add(transcript, 0x68a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7640),
                        0x60,
                        add(transcript, 0x7640),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x76a0), mload(add(transcript, 0x75c0)))
            mstore(add(transcript, 0x76c0), mload(add(transcript, 0x75e0)))
            mstore(add(transcript, 0x76e0), mload(add(transcript, 0x7640)))
            mstore(add(transcript, 0x7700), mload(add(transcript, 0x7660)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x76a0),
                        0x80,
                        add(transcript, 0x76a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7720), mload(add(transcript, 0x520)))
            mstore(add(transcript, 0x7740), mload(add(transcript, 0x540)))
            mstore(add(transcript, 0x7760), mload(add(transcript, 0x5da0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7720),
                        0x60,
                        add(transcript, 0x7720),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7780), mload(add(transcript, 0x76a0)))
            mstore(add(transcript, 0x77a0), mload(add(transcript, 0x76c0)))
            mstore(add(transcript, 0x77c0), mload(add(transcript, 0x7720)))
            mstore(add(transcript, 0x77e0), mload(add(transcript, 0x7740)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7780),
                        0x80,
                        add(transcript, 0x7780),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7800), mload(add(transcript, 0x860)))
            mstore(add(transcript, 0x7820), mload(add(transcript, 0x880)))
            mstore(add(transcript, 0x7840), mload(add(transcript, 0x6580)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7800),
                        0x60,
                        add(transcript, 0x7800),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7860), mload(add(transcript, 0x7780)))
            mstore(add(transcript, 0x7880), mload(add(transcript, 0x77a0)))
            mstore(add(transcript, 0x78a0), mload(add(transcript, 0x7800)))
            mstore(add(transcript, 0x78c0), mload(add(transcript, 0x7820)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7860),
                        0x80,
                        add(transcript, 0x7860),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x78e0), mload(add(transcript, 0x560)))
            mstore(add(transcript, 0x7900), mload(add(transcript, 0x580)))
            mstore(add(transcript, 0x7920), mload(add(transcript, 0x68c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x78e0),
                        0x60,
                        add(transcript, 0x78e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7940), mload(add(transcript, 0x7860)))
            mstore(add(transcript, 0x7960), mload(add(transcript, 0x7880)))
            mstore(add(transcript, 0x7980), mload(add(transcript, 0x78e0)))
            mstore(add(transcript, 0x79a0), mload(add(transcript, 0x7900)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7940),
                        0x80,
                        add(transcript, 0x7940),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x79c0), mload(add(transcript, 0x5a0)))
            mstore(add(transcript, 0x79e0), mload(add(transcript, 0x5c0)))
            mstore(add(transcript, 0x7a00), mload(add(transcript, 0x5e00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x79c0),
                        0x60,
                        add(transcript, 0x79c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7a20), mload(add(transcript, 0x7940)))
            mstore(add(transcript, 0x7a40), mload(add(transcript, 0x7960)))
            mstore(add(transcript, 0x7a60), mload(add(transcript, 0x79c0)))
            mstore(add(transcript, 0x7a80), mload(add(transcript, 0x79e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7a20),
                        0x80,
                        add(transcript, 0x7a20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7aa0), mload(add(transcript, 0x8a0)))
            mstore(add(transcript, 0x7ac0), mload(add(transcript, 0x8c0)))
            mstore(add(transcript, 0x7ae0), mload(add(transcript, 0x65a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7aa0),
                        0x60,
                        add(transcript, 0x7aa0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7b00), mload(add(transcript, 0x7a20)))
            mstore(add(transcript, 0x7b20), mload(add(transcript, 0x7a40)))
            mstore(add(transcript, 0x7b40), mload(add(transcript, 0x7aa0)))
            mstore(add(transcript, 0x7b60), mload(add(transcript, 0x7ac0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7b00),
                        0x80,
                        add(transcript, 0x7b00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7b80), mload(add(transcript, 0x5e0)))
            mstore(add(transcript, 0x7ba0), mload(add(transcript, 0x600)))
            mstore(add(transcript, 0x7bc0), mload(add(transcript, 0x68e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7b80),
                        0x60,
                        add(transcript, 0x7b80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7be0), mload(add(transcript, 0x7b00)))
            mstore(add(transcript, 0x7c00), mload(add(transcript, 0x7b20)))
            mstore(add(transcript, 0x7c20), mload(add(transcript, 0x7b80)))
            mstore(add(transcript, 0x7c40), mload(add(transcript, 0x7ba0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7be0),
                        0x80,
                        add(transcript, 0x7be0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7c60), mload(add(transcript, 0x620)))
            mstore(add(transcript, 0x7c80), mload(add(transcript, 0x640)))
            mstore(add(transcript, 0x7ca0), mload(add(transcript, 0x5e60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7c60),
                        0x60,
                        add(transcript, 0x7c60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7cc0), mload(add(transcript, 0x7be0)))
            mstore(add(transcript, 0x7ce0), mload(add(transcript, 0x7c00)))
            mstore(add(transcript, 0x7d00), mload(add(transcript, 0x7c60)))
            mstore(add(transcript, 0x7d20), mload(add(transcript, 0x7c80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7cc0),
                        0x80,
                        add(transcript, 0x7cc0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x7d40),
                0x2e3e5c40fadd76e4b04878299bb2a15f52cbf0230084ea6764650be04ea5ce7f
            )
            mstore(
                add(transcript, 0x7d60),
                0x26c1f96b5bb2e5d72acf3a6e67a061c5932029ceb3d9c66d3271e660fddd0920
            )
            mstore(add(transcript, 0x7d80), mload(add(transcript, 0x5e80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7d40),
                        0x60,
                        add(transcript, 0x7d40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7da0), mload(add(transcript, 0x7cc0)))
            mstore(add(transcript, 0x7dc0), mload(add(transcript, 0x7ce0)))
            mstore(add(transcript, 0x7de0), mload(add(transcript, 0x7d40)))
            mstore(add(transcript, 0x7e00), mload(add(transcript, 0x7d60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7da0),
                        0x80,
                        add(transcript, 0x7da0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x7e20),
                0x22b2cad036db34b22b7dd6d94284afba059f4f2e967b6f2d99d175f7bae1b7c7
            )
            mstore(
                add(transcript, 0x7e40),
                0x0b94967e731f5e590bb282b0a52b4d4536eb4f231c47fe368db940f958750dbf
            )
            mstore(add(transcript, 0x7e60), mload(add(transcript, 0x5ea0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7e20),
                        0x60,
                        add(transcript, 0x7e20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7e80), mload(add(transcript, 0x7da0)))
            mstore(add(transcript, 0x7ea0), mload(add(transcript, 0x7dc0)))
            mstore(add(transcript, 0x7ec0), mload(add(transcript, 0x7e20)))
            mstore(add(transcript, 0x7ee0), mload(add(transcript, 0x7e40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7e80),
                        0x80,
                        add(transcript, 0x7e80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x7f00),
                0x1e1afd3a1bc2648dbc827a6c5dcae3019463cc2b5068ca5f76bfdafeaadfebef
            )
            mstore(
                add(transcript, 0x7f20),
                0x128d256191472b14051fdfaf9a826010794af1203c93119dc76a215d96b07e36
            )
            mstore(add(transcript, 0x7f40), mload(add(transcript, 0x5ec0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7f00),
                        0x60,
                        add(transcript, 0x7f00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7f60), mload(add(transcript, 0x7e80)))
            mstore(add(transcript, 0x7f80), mload(add(transcript, 0x7ea0)))
            mstore(add(transcript, 0x7fa0), mload(add(transcript, 0x7f00)))
            mstore(add(transcript, 0x7fc0), mload(add(transcript, 0x7f20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7f60),
                        0x80,
                        add(transcript, 0x7f60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x7fe0),
                0x203875becc5b74f0fd8199cf98f950ec77731ceab126dd05030cf315377d63ff
            )
            mstore(
                add(transcript, 0x8000),
                0x0514c2585db3f7c02d81e5f4abe0f1077cc2e5da1f5d888619465cfb5d1274a2
            )
            mstore(add(transcript, 0x8020), mload(add(transcript, 0x5ee0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7fe0),
                        0x60,
                        add(transcript, 0x7fe0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8040), mload(add(transcript, 0x7f60)))
            mstore(add(transcript, 0x8060), mload(add(transcript, 0x7f80)))
            mstore(add(transcript, 0x8080), mload(add(transcript, 0x7fe0)))
            mstore(add(transcript, 0x80a0), mload(add(transcript, 0x8000)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8040),
                        0x80,
                        add(transcript, 0x8040),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x80c0),
                0x2d7c2eae889fcc481a3763ed0efb883c1d3014babaab576f7e4e755ee03a153a
            )
            mstore(
                add(transcript, 0x80e0),
                0x2f7dcb92d7ddae677f7c5769d621ea3e20636fd2dd85f5ba260419459d162d12
            )
            mstore(add(transcript, 0x8100), mload(add(transcript, 0x5f00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x80c0),
                        0x60,
                        add(transcript, 0x80c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8120), mload(add(transcript, 0x8040)))
            mstore(add(transcript, 0x8140), mload(add(transcript, 0x8060)))
            mstore(add(transcript, 0x8160), mload(add(transcript, 0x80c0)))
            mstore(add(transcript, 0x8180), mload(add(transcript, 0x80e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8120),
                        0x80,
                        add(transcript, 0x8120),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x81a0),
                0x2a47ec45e6b52cf48a2edd3e771069c44cc6184333daa7762c0cf4df7d347cfb
            )
            mstore(
                add(transcript, 0x81c0),
                0x2d2fe35c53e60a78d3837689482c5df3f50361694cdceb712ce4ec207d384981
            )
            mstore(add(transcript, 0x81e0), mload(add(transcript, 0x5f20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x81a0),
                        0x60,
                        add(transcript, 0x81a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8200), mload(add(transcript, 0x8120)))
            mstore(add(transcript, 0x8220), mload(add(transcript, 0x8140)))
            mstore(add(transcript, 0x8240), mload(add(transcript, 0x81a0)))
            mstore(add(transcript, 0x8260), mload(add(transcript, 0x81c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8200),
                        0x80,
                        add(transcript, 0x8200),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8280),
                0x1db490f08579ecd2f6f8a971f279fca0dfce03de1235aacc0925b6a9f9a7052c
            )
            mstore(
                add(transcript, 0x82a0),
                0x081193ecaeac0e0f10a6b51efb5e0911c1d53559ef322091dcbda0b04a00a12f
            )
            mstore(add(transcript, 0x82c0), mload(add(transcript, 0x5f40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8280),
                        0x60,
                        add(transcript, 0x8280),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x82e0), mload(add(transcript, 0x8200)))
            mstore(add(transcript, 0x8300), mload(add(transcript, 0x8220)))
            mstore(add(transcript, 0x8320), mload(add(transcript, 0x8280)))
            mstore(add(transcript, 0x8340), mload(add(transcript, 0x82a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x82e0),
                        0x80,
                        add(transcript, 0x82e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8360),
                0x2e1e4adedca0395127c816ca70aac35eda3425b343c548fe5a8f00ccca881e6f
            )
            mstore(
                add(transcript, 0x8380),
                0x0b82e03e3d54d79d1be9e738848b6f704ad3ab91e2916ed7db3f173dfcd935f5
            )
            mstore(add(transcript, 0x83a0), mload(add(transcript, 0x5f60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8360),
                        0x60,
                        add(transcript, 0x8360),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x83c0), mload(add(transcript, 0x82e0)))
            mstore(add(transcript, 0x83e0), mload(add(transcript, 0x8300)))
            mstore(add(transcript, 0x8400), mload(add(transcript, 0x8360)))
            mstore(add(transcript, 0x8420), mload(add(transcript, 0x8380)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x83c0),
                        0x80,
                        add(transcript, 0x83c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8440),
                0x0b4f5021e339a57b9b272f081763e728aa36663d30c3d5552a1549e41988fc52
            )
            mstore(
                add(transcript, 0x8460),
                0x08d38d27e6cb8f0c07014c643afffd156accfdb6ad471caf6259c8acefa568d3
            )
            mstore(add(transcript, 0x8480), mload(add(transcript, 0x5f80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8440),
                        0x60,
                        add(transcript, 0x8440),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x84a0), mload(add(transcript, 0x83c0)))
            mstore(add(transcript, 0x84c0), mload(add(transcript, 0x83e0)))
            mstore(add(transcript, 0x84e0), mload(add(transcript, 0x8440)))
            mstore(add(transcript, 0x8500), mload(add(transcript, 0x8460)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x84a0),
                        0x80,
                        add(transcript, 0x84a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8520),
                0x1509143200dfddcae0dca969d8044585c31e3a2906d0854afca516e6d333e3aa
            )
            mstore(
                add(transcript, 0x8540),
                0x005150b5d8143da94a82e949af39c5f33decbaa82c5e6db2f077883f0ba36af1
            )
            mstore(add(transcript, 0x8560), mload(add(transcript, 0x5fa0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8520),
                        0x60,
                        add(transcript, 0x8520),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8580), mload(add(transcript, 0x84a0)))
            mstore(add(transcript, 0x85a0), mload(add(transcript, 0x84c0)))
            mstore(add(transcript, 0x85c0), mload(add(transcript, 0x8520)))
            mstore(add(transcript, 0x85e0), mload(add(transcript, 0x8540)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8580),
                        0x80,
                        add(transcript, 0x8580),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8600),
                0x20a7b4465410abe6ed8207659a91f317250ad4db3fa50f33cbe798f1e09ee3e0
            )
            mstore(
                add(transcript, 0x8620),
                0x23b2897a3a69e91fdf8488879331d912764b59eb3e767afcb82d44d61c2b6fb3
            )
            mstore(add(transcript, 0x8640), mload(add(transcript, 0x5fc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8600),
                        0x60,
                        add(transcript, 0x8600),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8660), mload(add(transcript, 0x8580)))
            mstore(add(transcript, 0x8680), mload(add(transcript, 0x85a0)))
            mstore(add(transcript, 0x86a0), mload(add(transcript, 0x8600)))
            mstore(add(transcript, 0x86c0), mload(add(transcript, 0x8620)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8660),
                        0x80,
                        add(transcript, 0x8660),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x86e0),
                0x133c9665a4f4416705b037a39b5a1a3dad109ed6cacbc413e76eb481ac29c4d5
            )
            mstore(
                add(transcript, 0x8700),
                0x093f3e21c9dc8d6252a1b0a7b7c32f2bde49338d6f2720903997e58a159037bb
            )
            mstore(add(transcript, 0x8720), mload(add(transcript, 0x5fe0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x86e0),
                        0x60,
                        add(transcript, 0x86e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8740), mload(add(transcript, 0x8660)))
            mstore(add(transcript, 0x8760), mload(add(transcript, 0x8680)))
            mstore(add(transcript, 0x8780), mload(add(transcript, 0x86e0)))
            mstore(add(transcript, 0x87a0), mload(add(transcript, 0x8700)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8740),
                        0x80,
                        add(transcript, 0x8740),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x87c0),
                0x2426c25d443994622471fcf10d0b6088ea033670134de287af3cbb94de66e98d
            )
            mstore(
                add(transcript, 0x87e0),
                0x271994df2c6472c01a37bb40b9a528fb0313565dc71ffdb5050cc91de0c273cc
            )
            mstore(add(transcript, 0x8800), mload(add(transcript, 0x6000)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x87c0),
                        0x60,
                        add(transcript, 0x87c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8820), mload(add(transcript, 0x8740)))
            mstore(add(transcript, 0x8840), mload(add(transcript, 0x8760)))
            mstore(add(transcript, 0x8860), mload(add(transcript, 0x87c0)))
            mstore(add(transcript, 0x8880), mload(add(transcript, 0x87e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8820),
                        0x80,
                        add(transcript, 0x8820),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x88a0),
                0x0fd8dbf1a039efc6ad9b940a160514f85adbc4262397f4bd806aaf4961074d77
            )
            mstore(
                add(transcript, 0x88c0),
                0x29e32970534d60d392ad54685f37f566e172b7db0a492232440aa6d5b58f9f69
            )
            mstore(add(transcript, 0x88e0), mload(add(transcript, 0x6020)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x88a0),
                        0x60,
                        add(transcript, 0x88a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8900), mload(add(transcript, 0x8820)))
            mstore(add(transcript, 0x8920), mload(add(transcript, 0x8840)))
            mstore(add(transcript, 0x8940), mload(add(transcript, 0x88a0)))
            mstore(add(transcript, 0x8960), mload(add(transcript, 0x88c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8900),
                        0x80,
                        add(transcript, 0x8900),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8980),
                0x1b4c3b376f6620688e186f280ee33c75955cc7780bb842b0b157d212690d99b7
            )
            mstore(
                add(transcript, 0x89a0),
                0x0ed06ed6c61657663f2dccc793a60973b5d036fa71aa358814e9f9cfd9ec6890
            )
            mstore(add(transcript, 0x89c0), mload(add(transcript, 0x6040)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8980),
                        0x60,
                        add(transcript, 0x8980),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x89e0), mload(add(transcript, 0x8900)))
            mstore(add(transcript, 0x8a00), mload(add(transcript, 0x8920)))
            mstore(add(transcript, 0x8a20), mload(add(transcript, 0x8980)))
            mstore(add(transcript, 0x8a40), mload(add(transcript, 0x89a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x89e0),
                        0x80,
                        add(transcript, 0x89e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8a60),
                0x0b2eced924b664837429309216ea54bc3710114ea13cd52d2422e6e6426515d3
            )
            mstore(
                add(transcript, 0x8a80),
                0x0664614e0036527c9f3fceef51130c1bac2f475f44998b2bd151352471c59c42
            )
            mstore(add(transcript, 0x8aa0), mload(add(transcript, 0x6060)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8a60),
                        0x60,
                        add(transcript, 0x8a60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8ac0), mload(add(transcript, 0x89e0)))
            mstore(add(transcript, 0x8ae0), mload(add(transcript, 0x8a00)))
            mstore(add(transcript, 0x8b00), mload(add(transcript, 0x8a60)))
            mstore(add(transcript, 0x8b20), mload(add(transcript, 0x8a80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8ac0),
                        0x80,
                        add(transcript, 0x8ac0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8b40),
                0x1954516be75a98b530b7609718497ba83a23f0030fe6899615dcec57a843e9dc
            )
            mstore(
                add(transcript, 0x8b60),
                0x1cbbcc27067488df096b75b061de8dd950b82ecd9e3f98e55880cfcbf7c8d9f7
            )
            mstore(add(transcript, 0x8b80), mload(add(transcript, 0x6080)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8b40),
                        0x60,
                        add(transcript, 0x8b40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8ba0), mload(add(transcript, 0x8ac0)))
            mstore(add(transcript, 0x8bc0), mload(add(transcript, 0x8ae0)))
            mstore(add(transcript, 0x8be0), mload(add(transcript, 0x8b40)))
            mstore(add(transcript, 0x8c00), mload(add(transcript, 0x8b60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8ba0),
                        0x80,
                        add(transcript, 0x8ba0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8c20),
                0x173a8c225e3230e4487a937d257917aba0ff909583443e82f543e999d909aad5
            )
            mstore(
                add(transcript, 0x8c40),
                0x1e54e937f5d85d29331962fe087a4cfb707c55e58412b43c31a8d066daac616b
            )
            mstore(add(transcript, 0x8c60), mload(add(transcript, 0x60a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8c20),
                        0x60,
                        add(transcript, 0x8c20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8c80), mload(add(transcript, 0x8ba0)))
            mstore(add(transcript, 0x8ca0), mload(add(transcript, 0x8bc0)))
            mstore(add(transcript, 0x8cc0), mload(add(transcript, 0x8c20)))
            mstore(add(transcript, 0x8ce0), mload(add(transcript, 0x8c40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8c80),
                        0x80,
                        add(transcript, 0x8c80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8d00),
                0x16a5fecf118ef5be8fc1dab70d8d1d3c2d38d251944954d73c5f4c0a9b980891
            )
            mstore(
                add(transcript, 0x8d20),
                0x0c1b5f3265d566bdf8af4420fe4af54b8a5a7a70703ef7a83daa44d939f96a71
            )
            mstore(add(transcript, 0x8d40), mload(add(transcript, 0x60c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8d00),
                        0x60,
                        add(transcript, 0x8d00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8d60), mload(add(transcript, 0x8c80)))
            mstore(add(transcript, 0x8d80), mload(add(transcript, 0x8ca0)))
            mstore(add(transcript, 0x8da0), mload(add(transcript, 0x8d00)))
            mstore(add(transcript, 0x8dc0), mload(add(transcript, 0x8d20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8d60),
                        0x80,
                        add(transcript, 0x8d60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8de0),
                0x019a313143d98557b5ba022078b4118c73e759bc4c66d068e7471819fbbc0c9e
            )
            mstore(
                add(transcript, 0x8e00),
                0x0251f18a7aa64220e23c2451d31a8bd58770d9db3cfea30c906d6e6ac124dc17
            )
            mstore(add(transcript, 0x8e20), mload(add(transcript, 0x60e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8de0),
                        0x60,
                        add(transcript, 0x8de0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8e40), mload(add(transcript, 0x8d60)))
            mstore(add(transcript, 0x8e60), mload(add(transcript, 0x8d80)))
            mstore(add(transcript, 0x8e80), mload(add(transcript, 0x8de0)))
            mstore(add(transcript, 0x8ea0), mload(add(transcript, 0x8e00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8e40),
                        0x80,
                        add(transcript, 0x8e40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8ec0), mload(add(transcript, 0x980)))
            mstore(add(transcript, 0x8ee0), mload(add(transcript, 0x9a0)))
            mstore(add(transcript, 0x8f00), mload(add(transcript, 0x6100)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8ec0),
                        0x60,
                        add(transcript, 0x8ec0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8f20), mload(add(transcript, 0x8e40)))
            mstore(add(transcript, 0x8f40), mload(add(transcript, 0x8e60)))
            mstore(add(transcript, 0x8f60), mload(add(transcript, 0x8ec0)))
            mstore(add(transcript, 0x8f80), mload(add(transcript, 0x8ee0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8f20),
                        0x80,
                        add(transcript, 0x8f20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8fa0), mload(add(transcript, 0x9c0)))
            mstore(add(transcript, 0x8fc0), mload(add(transcript, 0x9e0)))
            mstore(add(transcript, 0x8fe0), mload(add(transcript, 0x6120)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8fa0),
                        0x60,
                        add(transcript, 0x8fa0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9000), mload(add(transcript, 0x8f20)))
            mstore(add(transcript, 0x9020), mload(add(transcript, 0x8f40)))
            mstore(add(transcript, 0x9040), mload(add(transcript, 0x8fa0)))
            mstore(add(transcript, 0x9060), mload(add(transcript, 0x8fc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9000),
                        0x80,
                        add(transcript, 0x9000),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9080), mload(add(transcript, 0xa00)))
            mstore(add(transcript, 0x90a0), mload(add(transcript, 0xa20)))
            mstore(add(transcript, 0x90c0), mload(add(transcript, 0x6140)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9080),
                        0x60,
                        add(transcript, 0x9080),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x90e0), mload(add(transcript, 0x9000)))
            mstore(add(transcript, 0x9100), mload(add(transcript, 0x9020)))
            mstore(add(transcript, 0x9120), mload(add(transcript, 0x9080)))
            mstore(add(transcript, 0x9140), mload(add(transcript, 0x90a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x90e0),
                        0x80,
                        add(transcript, 0x90e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9160), mload(add(transcript, 0xa40)))
            mstore(add(transcript, 0x9180), mload(add(transcript, 0xa60)))
            mstore(add(transcript, 0x91a0), mload(add(transcript, 0x6160)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9160),
                        0x60,
                        add(transcript, 0x9160),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x91c0), mload(add(transcript, 0x90e0)))
            mstore(add(transcript, 0x91e0), mload(add(transcript, 0x9100)))
            mstore(add(transcript, 0x9200), mload(add(transcript, 0x9160)))
            mstore(add(transcript, 0x9220), mload(add(transcript, 0x9180)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x91c0),
                        0x80,
                        add(transcript, 0x91c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9240), mload(add(transcript, 0x8e0)))
            mstore(add(transcript, 0x9260), mload(add(transcript, 0x900)))
            mstore(add(transcript, 0x9280), mload(add(transcript, 0x6180)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9240),
                        0x60,
                        add(transcript, 0x9240),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x92a0), mload(add(transcript, 0x91c0)))
            mstore(add(transcript, 0x92c0), mload(add(transcript, 0x91e0)))
            mstore(add(transcript, 0x92e0), mload(add(transcript, 0x9240)))
            mstore(add(transcript, 0x9300), mload(add(transcript, 0x9260)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x92a0),
                        0x80,
                        add(transcript, 0x92a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9320), mload(add(transcript, 0x1260)))
            mstore(add(transcript, 0x9340), mload(add(transcript, 0x1280)))
            mstore(add(transcript, 0x9360), mload(add(transcript, 0x6920)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9320),
                        0x60,
                        add(transcript, 0x9320),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9380), mload(add(transcript, 0x92a0)))
            mstore(add(transcript, 0x93a0), mload(add(transcript, 0x92c0)))
            mstore(add(transcript, 0x93c0), mload(add(transcript, 0x9320)))
            mstore(add(transcript, 0x93e0), mload(add(transcript, 0x9340)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9380),
                        0x80,
                        add(transcript, 0x9380),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9400), mload(add(transcript, 0x12a0)))
            mstore(add(transcript, 0x9420), mload(add(transcript, 0x12c0)))
            mstore(add(transcript, 0x9440), mload(add(transcript, 0x6960)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9400),
                        0x60,
                        add(transcript, 0x9400),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9460), mload(add(transcript, 0x9380)))
            mstore(add(transcript, 0x9480), mload(add(transcript, 0x93a0)))
            mstore(add(transcript, 0x94a0), mload(add(transcript, 0x9400)))
            mstore(add(transcript, 0x94c0), mload(add(transcript, 0x9420)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9460),
                        0x80,
                        add(transcript, 0x9460),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x94e0), mload(add(transcript, 0x12e0)))
            mstore(add(transcript, 0x9500), mload(add(transcript, 0x1300)))
            mstore(add(transcript, 0x9520), mload(add(transcript, 0x69a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x94e0),
                        0x60,
                        add(transcript, 0x94e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9540), mload(add(transcript, 0x9460)))
            mstore(add(transcript, 0x9560), mload(add(transcript, 0x9480)))
            mstore(add(transcript, 0x9580), mload(add(transcript, 0x94e0)))
            mstore(add(transcript, 0x95a0), mload(add(transcript, 0x9500)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9540),
                        0x80,
                        add(transcript, 0x9540),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x95c0), mload(add(transcript, 0x1320)))
            mstore(add(transcript, 0x95e0), mload(add(transcript, 0x1340)))
            mstore(add(transcript, 0x9600), mload(add(transcript, 0x69e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x95c0),
                        0x60,
                        add(transcript, 0x95c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9620), mload(add(transcript, 0x9540)))
            mstore(add(transcript, 0x9640), mload(add(transcript, 0x9560)))
            mstore(add(transcript, 0x9660), mload(add(transcript, 0x95c0)))
            mstore(add(transcript, 0x9680), mload(add(transcript, 0x95e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9620),
                        0x80,
                        add(transcript, 0x9620),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x96a0), mload(add(transcript, 0x12a0)))
            mstore(add(transcript, 0x96c0), mload(add(transcript, 0x12c0)))
            mstore(add(transcript, 0x96e0), mload(add(transcript, 0x63a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x96a0),
                        0x60,
                        add(transcript, 0x96a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9700), mload(add(transcript, 0x1260)))
            mstore(add(transcript, 0x9720), mload(add(transcript, 0x1280)))
            mstore(add(transcript, 0x9740), mload(add(transcript, 0x96a0)))
            mstore(add(transcript, 0x9760), mload(add(transcript, 0x96c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9700),
                        0x80,
                        add(transcript, 0x9700),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9780), mload(add(transcript, 0x12e0)))
            mstore(add(transcript, 0x97a0), mload(add(transcript, 0x1300)))
            mstore(add(transcript, 0x97c0), mload(add(transcript, 0x6600)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9780),
                        0x60,
                        add(transcript, 0x9780),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x97e0), mload(add(transcript, 0x9700)))
            mstore(add(transcript, 0x9800), mload(add(transcript, 0x9720)))
            mstore(add(transcript, 0x9820), mload(add(transcript, 0x9780)))
            mstore(add(transcript, 0x9840), mload(add(transcript, 0x97a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x97e0),
                        0x80,
                        add(transcript, 0x97e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9860), mload(add(transcript, 0x1320)))
            mstore(add(transcript, 0x9880), mload(add(transcript, 0x1340)))
            mstore(add(transcript, 0x98a0), mload(add(transcript, 0x67a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9860),
                        0x60,
                        add(transcript, 0x9860),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x98c0), mload(add(transcript, 0x97e0)))
            mstore(add(transcript, 0x98e0), mload(add(transcript, 0x9800)))
            mstore(add(transcript, 0x9900), mload(add(transcript, 0x9860)))
            mstore(add(transcript, 0x9920), mload(add(transcript, 0x9880)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x98c0),
                        0x80,
                        add(transcript, 0x98c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9940), mload(add(transcript, 0x9620)))
            mstore(add(transcript, 0x9960), mload(add(transcript, 0x9640)))
            mstore(add(transcript, 0x9980), mload(add(transcript, 0x98c0)))
            mstore(add(transcript, 0x99a0), mload(add(transcript, 0x98e0)))
            mstore(add(transcript, 0x99c0), mload(add(transcript, 0x13c0)))
            mstore(add(transcript, 0x99e0), mload(add(transcript, 0x13e0)))
            mstore(add(transcript, 0x9a00), mload(add(transcript, 0x1400)))
            mstore(add(transcript, 0x9a20), mload(add(transcript, 0x1420)))
            mstore(
                add(transcript, 0x9a40),
                keccak256(add(transcript, 0x9940), 256)
            )
            mstore(add(transcript, 0x9a60), mod(mload(39488), f_q))
            mstore(
                add(transcript, 0x9a80),
                mulmod(
                    mload(add(transcript, 0x9a60)),
                    mload(add(transcript, 0x9a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x9aa0),
                mulmod(1, mload(add(transcript, 0x9a60)), f_q)
            )
            mstore(add(transcript, 0x9ac0), mload(add(transcript, 0x99c0)))
            mstore(add(transcript, 0x9ae0), mload(add(transcript, 0x99e0)))
            mstore(add(transcript, 0x9b00), mload(add(transcript, 0x9aa0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9ac0),
                        0x60,
                        add(transcript, 0x9ac0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9b20), mload(add(transcript, 0x9940)))
            mstore(add(transcript, 0x9b40), mload(add(transcript, 0x9960)))
            mstore(add(transcript, 0x9b60), mload(add(transcript, 0x9ac0)))
            mstore(add(transcript, 0x9b80), mload(add(transcript, 0x9ae0)))
            // success := and(
            //     eq(
            //         staticcall(
            //             gas(),
            //             0x6,
            //             add(transcript, 0x9b20),
            //             0x80,
            //             add(transcript, 0x9b20),
            //             0x40
            //         ),
            //         1
            //     ),
            //     success
            // )
            // mstore(add(transcript, 0x9ba0), mload(add(transcript, 0x9a00)))
            // mstore(add(transcript, 0x9bc0), mload(add(transcript, 0x9a20)))
            mstore(add(transcript, 0x9be0), mload(add(transcript, 0x9aa0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9ba0),
                        0x60,
                        add(transcript, 0x9ba0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9c00), mload(add(transcript, 0x9980)))
            mstore(add(transcript, 0x9c20), mload(add(transcript, 0x99a0)))
            mstore(add(transcript, 0x9c40), mload(add(transcript, 0x9ba0)))
            mstore(add(transcript, 0x9c60), mload(add(transcript, 0x9bc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9c00),
                        0x80,
                        add(transcript, 0x9c00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9c80), mload(add(transcript, 0x9b20)))
            mstore(add(transcript, 0x9ca0), mload(add(transcript, 0x9b40)))
            mstore(
                add(transcript, 0x9cc0),
                0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
            )
            mstore(
                add(transcript, 0x9ce0),
                0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
            )
            mstore(
                add(transcript, 0x9d00),
                0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
            )
            mstore(
                add(transcript, 0x9d20),
                0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
            )
            mstore(add(transcript, 0x9d40), mload(add(transcript, 0x9c00)))
            mstore(add(transcript, 0x9d60), mload(add(transcript, 0x9c20)))
            mstore(
                add(transcript, 0x9d80),
                0x1cf8832646b03608390dd9a6f7c6de581e065a2c99be3cd7e2259c0738c19051
            )
            mstore(
                add(transcript, 0x9da0),
                0x068db4b87c697bd9906371fc2e24e522e20ca527952bfe058b3225974acf545f
            )
            mstore(
                add(transcript, 0x9dc0),
                0x01fdf661dc9860278308a39ac4e8214b55996acd015119a41baf7dc2ecbcd71b
            )
            mstore(
                add(transcript, 0x9de0),
                0x2f69939a4701e1090159fcd62d8804f026626380dc72d6f2fa9ea681671c8800
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x8,
                        add(transcript, 0x9c80),
                        0x180,
                        add(transcript, 0x9c80),
                        0x20
                    ),
                    1
                ),
                success
            )
            success := and(eq(mload(add(transcript, 0x9c80)), 1), success)
        }
        return success;
    }
}
