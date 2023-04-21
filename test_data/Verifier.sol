// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract Verifier {
    function verify(
        uint256[] memory pubInputs,
        bytes memory proof
    ) public view returns (bool) {
        bool success = true;
        bytes32[1262] memory transcript;
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
                21630609089637726277693399347439108634721822533684158267839943824881962284993
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
                addmod(
                    mload(add(transcript, 0x1700)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1740),
                mulmod(
                    mload(add(transcript, 0x1720)),
                    21888240262557392955334514970720457388010314637169927192662615958087340972065,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1760),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    21710372849001950800533397158415938114909991150039389063546734567764856596059,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1780),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    177870022837324421713008586841336973638373250376645280151469618810951899558,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17a0),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    1887003188133998471169152042388914354640772748308168868301418279904560637395,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17c0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    20001239683705276751077253702868360733907591652107865475396785906671247858222,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17e0),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    2785514556381676080176937710880804108647911392478702105860685610379369825016,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1800),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    19102728315457599142069468034376470979900453007937332237837518576196438670601,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1820),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    14655294445420895451632927078981340937842238432098198055057679026789553137428,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1840),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    7232948426418379770613478666275934150706125968317836288640525159786255358189,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1860),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    8734126352828345679573237859165904705806588461301144420590422589042130041188,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1880),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    13154116519010929542673167886091370382741775939114889923107781597533678454429,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18a0),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    9741553891420464328295280489650144566903017206473301385034033384879943874347,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18c0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    12146688980418810893951125255607130521645347193942732958664170801695864621270,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18e0),
                mulmod(mload(add(transcript, 0x1740)), 1, f_q)
            )
            mstore(
                add(transcript, 0x1900),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1920),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    8374374965308410102411073611984011876711565317741801500439755773472076597347,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1940),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    13513867906530865119835332133273263211836799082674232843258448413103731898270,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1960),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    11211301017135681023579411905410872569206244553457844956874280139879520583390,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1980),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    10676941854703594198666993839846402519342119846958189386823924046696287912227,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19a0),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    3615478808282855240548287271348143516886772452944084747768312988864436725401,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19c0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    18272764063556419981698118473909131571661591947471949595929891197711371770216,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19e0),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    1426404432721484388505361748317961535523355871255605456897797744433766488507,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a00),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    20461838439117790833741043996939313553025008529160428886800406442142042007110,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a20),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    216092043779272773661818549620449970334216366264741118684015851799902419467,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a40),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    21672150828060002448584587195636825118214148034151293225014188334775906076150,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a60),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    12619617507853212586156872920672483948819476989779550311307282715684870266992,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a80),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    9268625363986062636089532824584791139728887410636484032390921470890938228625,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1aa0),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    18610195890048912503953886742825279624920778288956610528523679659246523534888,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ac0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    3278046981790362718292519002431995463627586111459423815174524527329284960729,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ae0),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    19032961837237948602743626455740240236231119053033140765040043513661803148152,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b00),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    2855281034601326619502779289517034852317245347382893578658160672914005347465,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b20),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    14875928112196239563830800280253496262679717528621719058794366823499719730250,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b40),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    7012314759643035658415605465003778825868646871794315284903837363076088765367,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b60),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    915149353520972163646494413843788069594022902357002628455555785223409501882,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b80),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    20973093518318303058599911331413487018954341498059031715242648401352398993735,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ba0),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    5522161504810533295870699551020523636289972223872138525048055197429246400245,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1bc0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    16366081367028741926375706194236751452258392176543895818650148989146562095372,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1be0),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    3766081621734395783232337525162072736827576297943013392955872170138036189193,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c00),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    18122161250104879439014068220095202351720788102473020950742332016437772306424,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c20),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    9100833993744738801214480881117348002768153232283708533639316963648253510584,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c40),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    12787408878094536421031924864139927085780211168132325810058887222927554985033,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c60),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    4245441013247250116003069945606352967193023389718465410501109428393342802981,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c80),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    17642801858592025106243335799650922121355341010697568933197094758182465692636,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ca0),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    6132660129994545119218258312491950835441607143741804980633129304664017206141,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1cc0),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    15755582741844730103028147432765324253106757256674229363065074881911791289476,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ce0),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    5854133144571823792863860130267644613802765696134002830362054821530146160770,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d00),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    16034109727267451429382545614989630474745598704282031513336149365045662334847,
                    f_q
                )
            )
            {
                let prod := mload(add(transcript, 0x1780))
                prod := mulmod(mload(add(transcript, 0x17c0)), prod, f_q)
                mstore(add(transcript, 0x1d20), prod)
                prod := mulmod(mload(add(transcript, 0x1800)), prod, f_q)
                mstore(add(transcript, 0x1d40), prod)
                prod := mulmod(mload(add(transcript, 0x1840)), prod, f_q)
                mstore(add(transcript, 0x1d60), prod)
                prod := mulmod(mload(add(transcript, 0x1880)), prod, f_q)
                mstore(add(transcript, 0x1d80), prod)
                prod := mulmod(mload(add(transcript, 0x18c0)), prod, f_q)
                mstore(add(transcript, 0x1da0), prod)
                prod := mulmod(mload(add(transcript, 0x1900)), prod, f_q)
                mstore(add(transcript, 0x1dc0), prod)
                prod := mulmod(mload(add(transcript, 0x1940)), prod, f_q)
                mstore(add(transcript, 0x1de0), prod)
                prod := mulmod(mload(add(transcript, 0x1980)), prod, f_q)
                mstore(add(transcript, 0x1e00), prod)
                prod := mulmod(mload(add(transcript, 0x19c0)), prod, f_q)
                mstore(add(transcript, 0x1e20), prod)
                prod := mulmod(mload(add(transcript, 0x1a00)), prod, f_q)
                mstore(add(transcript, 0x1e40), prod)
                prod := mulmod(mload(add(transcript, 0x1a40)), prod, f_q)
                mstore(add(transcript, 0x1e60), prod)
                prod := mulmod(mload(add(transcript, 0x1a80)), prod, f_q)
                mstore(add(transcript, 0x1e80), prod)
                prod := mulmod(mload(add(transcript, 0x1ac0)), prod, f_q)
                mstore(add(transcript, 0x1ea0), prod)
                prod := mulmod(mload(add(transcript, 0x1b00)), prod, f_q)
                mstore(add(transcript, 0x1ec0), prod)
                prod := mulmod(mload(add(transcript, 0x1b40)), prod, f_q)
                mstore(add(transcript, 0x1ee0), prod)
                prod := mulmod(mload(add(transcript, 0x1b80)), prod, f_q)
                mstore(add(transcript, 0x1f00), prod)
                prod := mulmod(mload(add(transcript, 0x1bc0)), prod, f_q)
                mstore(add(transcript, 0x1f20), prod)
                prod := mulmod(mload(add(transcript, 0x1c00)), prod, f_q)
                mstore(add(transcript, 0x1f40), prod)
                prod := mulmod(mload(add(transcript, 0x1c40)), prod, f_q)
                mstore(add(transcript, 0x1f60), prod)
                prod := mulmod(mload(add(transcript, 0x1c80)), prod, f_q)
                mstore(add(transcript, 0x1f80), prod)
                prod := mulmod(mload(add(transcript, 0x1cc0)), prod, f_q)
                mstore(add(transcript, 0x1fa0), prod)
                prod := mulmod(mload(add(transcript, 0x1d00)), prod, f_q)
                mstore(add(transcript, 0x1fc0), prod)
                prod := mulmod(mload(add(transcript, 0x1720)), prod, f_q)
                mstore(add(transcript, 0x1fe0), prod)
            }
            mstore(add(transcript, 0x2020), 32)
            mstore(add(transcript, 0x2040), 32)
            mstore(add(transcript, 0x2060), 32)
            mstore(add(transcript, 0x2080), mload(add(transcript, 0x1fe0)))
            mstore(
                add(transcript, 0x20a0),
                21888242871839275222246405745257275088548364400416034343698204186575808495615
            )
            mstore(
                add(transcript, 0x20c0),
                21888242871839275222246405745257275088548364400416034343698204186575808495617
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x5,
                        add(transcript, 0x2020),
                        0xc0,
                        add(transcript, 0x2000),
                        0x20
                    ),
                    1
                ),
                success
            )
            {
                let inv := mload(add(transcript, 0x2000))
                let v
                v := mload(add(transcript, 0x1720))
                mstore(
                    add(transcript, 0x1720),
                    mulmod(mload(add(transcript, 0x1fc0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1d00))
                mstore(
                    add(transcript, 0x1d00),
                    mulmod(mload(add(transcript, 0x1fa0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1cc0))
                mstore(
                    add(transcript, 0x1cc0),
                    mulmod(mload(add(transcript, 0x1f80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1c80))
                mstore(
                    add(transcript, 0x1c80),
                    mulmod(mload(add(transcript, 0x1f60)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1c40))
                mstore(
                    add(transcript, 0x1c40),
                    mulmod(mload(add(transcript, 0x1f40)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1c00))
                mstore(
                    add(transcript, 0x1c00),
                    mulmod(mload(add(transcript, 0x1f20)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1bc0))
                mstore(
                    add(transcript, 0x1bc0),
                    mulmod(mload(add(transcript, 0x1f00)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1b80))
                mstore(
                    add(transcript, 0x1b80),
                    mulmod(mload(add(transcript, 0x1ee0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1b40))
                mstore(
                    add(transcript, 0x1b40),
                    mulmod(mload(add(transcript, 0x1ec0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1b00))
                mstore(
                    add(transcript, 0x1b00),
                    mulmod(mload(add(transcript, 0x1ea0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1ac0))
                mstore(
                    add(transcript, 0x1ac0),
                    mulmod(mload(add(transcript, 0x1e80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1a80))
                mstore(
                    add(transcript, 0x1a80),
                    mulmod(mload(add(transcript, 0x1e60)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1a40))
                mstore(
                    add(transcript, 0x1a40),
                    mulmod(mload(add(transcript, 0x1e40)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1a00))
                mstore(
                    add(transcript, 0x1a00),
                    mulmod(mload(add(transcript, 0x1e20)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x19c0))
                mstore(
                    add(transcript, 0x19c0),
                    mulmod(mload(add(transcript, 0x1e00)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1980))
                mstore(
                    add(transcript, 0x1980),
                    mulmod(mload(add(transcript, 0x1de0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1940))
                mstore(
                    add(transcript, 0x1940),
                    mulmod(mload(add(transcript, 0x1dc0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1900))
                mstore(
                    add(transcript, 0x1900),
                    mulmod(mload(add(transcript, 0x1da0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x18c0))
                mstore(
                    add(transcript, 0x18c0),
                    mulmod(mload(add(transcript, 0x1d80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1880))
                mstore(
                    add(transcript, 0x1880),
                    mulmod(mload(add(transcript, 0x1d60)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1840))
                mstore(
                    add(transcript, 0x1840),
                    mulmod(mload(add(transcript, 0x1d40)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1800))
                mstore(
                    add(transcript, 0x1800),
                    mulmod(mload(add(transcript, 0x1d20)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x17c0))
                mstore(
                    add(transcript, 0x17c0),
                    mulmod(mload(add(transcript, 0x1780)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                mstore(add(transcript, 0x1780), inv)
            }
            mstore(
                add(transcript, 0x20e0),
                mulmod(
                    mload(add(transcript, 0x1760)),
                    mload(add(transcript, 0x1780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2100),
                mulmod(
                    mload(add(transcript, 0x17a0)),
                    mload(add(transcript, 0x17c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2120),
                mulmod(
                    mload(add(transcript, 0x17e0)),
                    mload(add(transcript, 0x1800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2140),
                mulmod(
                    mload(add(transcript, 0x1820)),
                    mload(add(transcript, 0x1840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2160),
                mulmod(
                    mload(add(transcript, 0x1860)),
                    mload(add(transcript, 0x1880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2180),
                mulmod(
                    mload(add(transcript, 0x18a0)),
                    mload(add(transcript, 0x18c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21a0),
                mulmod(
                    mload(add(transcript, 0x18e0)),
                    mload(add(transcript, 0x1900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21c0),
                mulmod(
                    mload(add(transcript, 0x1920)),
                    mload(add(transcript, 0x1940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21e0),
                mulmod(
                    mload(add(transcript, 0x1960)),
                    mload(add(transcript, 0x1980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2200),
                mulmod(
                    mload(add(transcript, 0x19a0)),
                    mload(add(transcript, 0x19c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2220),
                mulmod(
                    mload(add(transcript, 0x19e0)),
                    mload(add(transcript, 0x1a00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2240),
                mulmod(
                    mload(add(transcript, 0x1a20)),
                    mload(add(transcript, 0x1a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2260),
                mulmod(
                    mload(add(transcript, 0x1a60)),
                    mload(add(transcript, 0x1a80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2280),
                mulmod(
                    mload(add(transcript, 0x1aa0)),
                    mload(add(transcript, 0x1ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22a0),
                mulmod(
                    mload(add(transcript, 0x1ae0)),
                    mload(add(transcript, 0x1b00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22c0),
                mulmod(
                    mload(add(transcript, 0x1b20)),
                    mload(add(transcript, 0x1b40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22e0),
                mulmod(
                    mload(add(transcript, 0x1b60)),
                    mload(add(transcript, 0x1b80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2300),
                mulmod(
                    mload(add(transcript, 0x1ba0)),
                    mload(add(transcript, 0x1bc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2320),
                mulmod(
                    mload(add(transcript, 0x1be0)),
                    mload(add(transcript, 0x1c00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2340),
                mulmod(
                    mload(add(transcript, 0x1c20)),
                    mload(add(transcript, 0x1c40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2360),
                mulmod(
                    mload(add(transcript, 0x1c60)),
                    mload(add(transcript, 0x1c80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2380),
                mulmod(
                    mload(add(transcript, 0x1ca0)),
                    mload(add(transcript, 0x1cc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23a0),
                mulmod(
                    mload(add(transcript, 0x1ce0)),
                    mload(add(transcript, 0x1d00)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x21a0)),
                    mload(add(transcript, 0x20)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x21c0)),
                        mload(add(transcript, 0x40)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x21e0)),
                        mload(add(transcript, 0x60)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2200)),
                        mload(add(transcript, 0x80)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2220)),
                        mload(add(transcript, 0xa0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2240)),
                        mload(add(transcript, 0xc0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2260)),
                        mload(add(transcript, 0xe0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2280)),
                        mload(add(transcript, 0x100)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x22a0)),
                        mload(add(transcript, 0x120)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x22c0)),
                        mload(add(transcript, 0x140)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x22e0)),
                        mload(add(transcript, 0x160)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2300)),
                        mload(add(transcript, 0x180)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2320)),
                        mload(add(transcript, 0x1a0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2340)),
                        mload(add(transcript, 0x1c0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2360)),
                        mload(add(transcript, 0x1e0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2380)),
                        mload(add(transcript, 0x200)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x23a0)),
                        mload(add(transcript, 0x220)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x23c0), result)
            }
            mstore(
                add(transcript, 0x23e0),
                mulmod(
                    mload(add(transcript, 0xba0)),
                    mload(add(transcript, 0xae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2400),
                mulmod(
                    mload(add(transcript, 0xbc0)),
                    mload(add(transcript, 0xb00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2420),
                addmod(
                    mload(add(transcript, 0x23e0)),
                    mload(add(transcript, 0x2400)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2440),
                mulmod(
                    mload(add(transcript, 0xbe0)),
                    mload(add(transcript, 0xb20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2460),
                addmod(
                    mload(add(transcript, 0x2420)),
                    mload(add(transcript, 0x2440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2480),
                mulmod(
                    mload(add(transcript, 0xc00)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24a0),
                addmod(
                    mload(add(transcript, 0x2460)),
                    mload(add(transcript, 0x2480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24c0),
                mulmod(
                    mload(add(transcript, 0xc20)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24e0),
                addmod(
                    mload(add(transcript, 0x24a0)),
                    mload(add(transcript, 0x24c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2500),
                mulmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0xae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2520),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    mload(add(transcript, 0x2500)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2540),
                addmod(
                    mload(add(transcript, 0x24e0)),
                    mload(add(transcript, 0x2520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2560),
                mulmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0xb20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2580),
                mulmod(
                    mload(add(transcript, 0xc80)),
                    mload(add(transcript, 0x2560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25a0),
                addmod(
                    mload(add(transcript, 0x2540)),
                    mload(add(transcript, 0x2580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25c0),
                mulmod(
                    mload(add(transcript, 0xb80)),
                    mload(add(transcript, 0xc40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25e0),
                addmod(
                    mload(add(transcript, 0x25a0)),
                    mload(add(transcript, 0x25c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2600),
                addmod(
                    mload(add(transcript, 0x25e0)),
                    mload(add(transcript, 0xca0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2620),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x2600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2640),
                addmod(1, sub(f_q, mload(add(transcript, 0xe40))), f_q)
            )
            mstore(
                add(transcript, 0x2660),
                mulmod(
                    mload(add(transcript, 0x2640)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2680),
                addmod(
                    mload(add(transcript, 0x2620)),
                    mload(add(transcript, 0x2660)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26a0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x2680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26c0),
                mulmod(
                    mload(add(transcript, 0xea0)),
                    mload(add(transcript, 0xea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26e0),
                addmod(
                    mload(add(transcript, 0x26c0)),
                    sub(f_q, mload(add(transcript, 0xea0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2700),
                mulmod(
                    mload(add(transcript, 0x26e0)),
                    mload(add(transcript, 0x20e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2720),
                addmod(
                    mload(add(transcript, 0x26a0)),
                    mload(add(transcript, 0x2700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2740),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x2720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2760),
                addmod(
                    mload(add(transcript, 0xea0)),
                    sub(f_q, mload(add(transcript, 0xe80))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2780),
                mulmod(
                    mload(add(transcript, 0x2760)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27a0),
                addmod(
                    mload(add(transcript, 0x2740)),
                    mload(add(transcript, 0x2780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27c0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x27a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27e0),
                addmod(1, sub(f_q, mload(add(transcript, 0x20e0))), f_q)
            )
            mstore(
                add(transcript, 0x2800),
                addmod(
                    mload(add(transcript, 0x2100)),
                    mload(add(transcript, 0x2120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2820),
                addmod(
                    mload(add(transcript, 0x2800)),
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
                    mload(add(transcript, 0x27e0)),
                    sub(f_q, mload(add(transcript, 0x2860))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28a0),
                mulmod(
                    mload(add(transcript, 0xd80)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28c0),
                addmod(
                    mload(add(transcript, 0xae0)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28e0),
                addmod(
                    mload(add(transcript, 0x28c0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2900),
                mulmod(
                    mload(add(transcript, 0xda0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2920),
                addmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0x2900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2940),
                addmod(
                    mload(add(transcript, 0x2920)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2960),
                mulmod(
                    mload(add(transcript, 0x2940)),
                    mload(add(transcript, 0x28e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2980),
                mulmod(
                    mload(add(transcript, 0xdc0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29a0),
                addmod(
                    mload(add(transcript, 0xb20)),
                    mload(add(transcript, 0x2980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29c0),
                addmod(
                    mload(add(transcript, 0x29a0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29e0),
                mulmod(
                    mload(add(transcript, 0x29c0)),
                    mload(add(transcript, 0x2960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a00),
                mulmod(
                    mload(add(transcript, 0x29e0)),
                    mload(add(transcript, 0xe60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a20),
                mulmod(1, mload(add(transcript, 0x680)), f_q)
            )
            mstore(
                add(transcript, 0x2a40),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a60),
                addmod(
                    mload(add(transcript, 0xae0)),
                    mload(add(transcript, 0x2a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a80),
                addmod(
                    mload(add(transcript, 0x2a60)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2aa0),
                mulmod(
                    4131629893567559867359510883348571134090853742863529169391034518566172092834,
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ac0),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ae0),
                addmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0x2ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b00),
                addmod(
                    mload(add(transcript, 0x2ae0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b20),
                mulmod(
                    mload(add(transcript, 0x2b00)),
                    mload(add(transcript, 0x2a80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b40),
                mulmod(
                    8910878055287538404433155982483128285667088683464058436815641868457422632747,
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b60),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2b40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b80),
                addmod(
                    mload(add(transcript, 0xb20)),
                    mload(add(transcript, 0x2b60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ba0),
                addmod(
                    mload(add(transcript, 0x2b80)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2bc0),
                mulmod(
                    mload(add(transcript, 0x2ba0)),
                    mload(add(transcript, 0x2b20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2be0),
                mulmod(
                    mload(add(transcript, 0x2bc0)),
                    mload(add(transcript, 0xe40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c00),
                addmod(
                    mload(add(transcript, 0x2a00)),
                    sub(f_q, mload(add(transcript, 0x2be0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c20),
                mulmod(
                    mload(add(transcript, 0x2c00)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c40),
                addmod(
                    mload(add(transcript, 0x27c0)),
                    mload(add(transcript, 0x2c20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c60),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x2c40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c80),
                mulmod(
                    mload(add(transcript, 0xde0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ca0),
                addmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0x2c80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2cc0),
                addmod(
                    mload(add(transcript, 0x2ca0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ce0),
                mulmod(
                    mload(add(transcript, 0xe00)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d00),
                addmod(
                    mload(add(transcript, 0xb60)),
                    mload(add(transcript, 0x2ce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d20),
                addmod(
                    mload(add(transcript, 0x2d00)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d40),
                mulmod(
                    mload(add(transcript, 0x2d20)),
                    mload(add(transcript, 0x2cc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d60),
                mulmod(
                    mload(add(transcript, 0xe20)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d80),
                addmod(
                    mload(add(transcript, 0x23c0)),
                    mload(add(transcript, 0x2d60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2da0),
                addmod(
                    mload(add(transcript, 0x2d80)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2dc0),
                mulmod(
                    mload(add(transcript, 0x2da0)),
                    mload(add(transcript, 0x2d40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2de0),
                mulmod(
                    mload(add(transcript, 0x2dc0)),
                    mload(add(transcript, 0xec0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e00),
                mulmod(
                    11166246659983828508719468090013646171463329086121580628794302409516816350802,
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e20),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2e00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e40),
                addmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0x2e20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e60),
                addmod(
                    mload(add(transcript, 0x2e40)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e80),
                mulmod(
                    284840088355319032285349970403338060113257071685626700086398481893096618818,
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ea0),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2e80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ec0),
                addmod(
                    mload(add(transcript, 0xb60)),
                    mload(add(transcript, 0x2ea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ee0),
                addmod(
                    mload(add(transcript, 0x2ec0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f00),
                mulmod(
                    mload(add(transcript, 0x2ee0)),
                    mload(add(transcript, 0x2e60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f20),
                mulmod(
                    21134065618345176623193549882539580312263652408302468683943992798037078993309,
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f40),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x2f20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f60),
                addmod(
                    mload(add(transcript, 0x23c0)),
                    mload(add(transcript, 0x2f40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f80),
                addmod(
                    mload(add(transcript, 0x2f60)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fa0),
                mulmod(
                    mload(add(transcript, 0x2f80)),
                    mload(add(transcript, 0x2f00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fc0),
                mulmod(
                    mload(add(transcript, 0x2fa0)),
                    mload(add(transcript, 0xea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fe0),
                addmod(
                    mload(add(transcript, 0x2de0)),
                    sub(f_q, mload(add(transcript, 0x2fc0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3000),
                mulmod(
                    mload(add(transcript, 0x2fe0)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3020),
                addmod(
                    mload(add(transcript, 0x2c60)),
                    mload(add(transcript, 0x3000)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3040),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3060),
                addmod(1, sub(f_q, mload(add(transcript, 0xee0))), f_q)
            )
            mstore(
                add(transcript, 0x3080),
                mulmod(
                    mload(add(transcript, 0x3060)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x30a0),
                addmod(
                    mload(add(transcript, 0x3040)),
                    mload(add(transcript, 0x3080)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x30c0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x30a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x30e0),
                mulmod(
                    mload(add(transcript, 0xee0)),
                    mload(add(transcript, 0xee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3100),
                addmod(
                    mload(add(transcript, 0x30e0)),
                    sub(f_q, mload(add(transcript, 0xee0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3120),
                mulmod(
                    mload(add(transcript, 0x3100)),
                    mload(add(transcript, 0x20e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3140),
                addmod(
                    mload(add(transcript, 0x30c0)),
                    mload(add(transcript, 0x3120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3160),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3140)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3180),
                addmod(
                    mload(add(transcript, 0xf20)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x31a0),
                mulmod(
                    mload(add(transcript, 0x3180)),
                    mload(add(transcript, 0xf00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x31c0),
                addmod(
                    mload(add(transcript, 0xf60)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x31e0),
                mulmod(
                    mload(add(transcript, 0x31c0)),
                    mload(add(transcript, 0x31a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3200),
                mulmod(5, mload(add(transcript, 0xd20)), f_q)
            )
            mstore(
                add(transcript, 0x3220),
                mulmod(
                    mload(add(transcript, 0x3a0)),
                    mload(add(transcript, 0x3200)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3240),
                mulmod(
                    mload(add(transcript, 0xae0)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3260),
                addmod(
                    mload(add(transcript, 0x3220)),
                    mload(add(transcript, 0x3240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3280),
                addmod(
                    mload(add(transcript, 0x3260)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x32a0),
                mulmod(
                    mload(add(transcript, 0x3280)),
                    mload(add(transcript, 0xee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x32c0),
                mulmod(
                    mload(add(transcript, 0x3a0)),
                    mload(add(transcript, 0xcc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x32e0),
                addmod(
                    mload(add(transcript, 0x32c0)),
                    mload(add(transcript, 0xce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3300),
                addmod(
                    mload(add(transcript, 0x32e0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3320),
                mulmod(
                    mload(add(transcript, 0x3300)),
                    mload(add(transcript, 0x32a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3340),
                addmod(
                    mload(add(transcript, 0x31e0)),
                    sub(f_q, mload(add(transcript, 0x3320))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3360),
                mulmod(
                    mload(add(transcript, 0x3340)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3380),
                addmod(
                    mload(add(transcript, 0x3160)),
                    mload(add(transcript, 0x3360)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x33a0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x33c0),
                addmod(
                    mload(add(transcript, 0xf20)),
                    sub(f_q, mload(add(transcript, 0xf60))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x33e0),
                mulmod(
                    mload(add(transcript, 0x33c0)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3400),
                addmod(
                    mload(add(transcript, 0x33a0)),
                    mload(add(transcript, 0x33e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3420),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3400)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3440),
                mulmod(
                    mload(add(transcript, 0x33c0)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3460),
                addmod(
                    mload(add(transcript, 0xf20)),
                    sub(f_q, mload(add(transcript, 0xf40))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3480),
                mulmod(
                    mload(add(transcript, 0x3460)),
                    mload(add(transcript, 0x3440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x34a0),
                addmod(
                    mload(add(transcript, 0x3420)),
                    mload(add(transcript, 0x3480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x34c0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x34a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x34e0),
                addmod(1, sub(f_q, mload(add(transcript, 0xf80))), f_q)
            )
            mstore(
                add(transcript, 0x3500),
                mulmod(
                    mload(add(transcript, 0x34e0)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3520),
                addmod(
                    mload(add(transcript, 0x34c0)),
                    mload(add(transcript, 0x3500)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3540),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3560),
                mulmod(
                    mload(add(transcript, 0xf80)),
                    mload(add(transcript, 0xf80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3580),
                addmod(
                    mload(add(transcript, 0x3560)),
                    sub(f_q, mload(add(transcript, 0xf80))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x35a0),
                mulmod(
                    mload(add(transcript, 0x3580)),
                    mload(add(transcript, 0x20e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x35c0),
                addmod(
                    mload(add(transcript, 0x3540)),
                    mload(add(transcript, 0x35a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x35e0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x35c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3600),
                addmod(
                    mload(add(transcript, 0xfc0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3620),
                mulmod(
                    mload(add(transcript, 0x3600)),
                    mload(add(transcript, 0xfa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3640),
                addmod(
                    mload(add(transcript, 0x1000)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3660),
                mulmod(
                    mload(add(transcript, 0x3640)),
                    mload(add(transcript, 0x3620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3680),
                mulmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x36a0),
                addmod(
                    mload(add(transcript, 0x3220)),
                    mload(add(transcript, 0x3680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x36c0),
                addmod(
                    mload(add(transcript, 0x36a0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x36e0),
                mulmod(
                    mload(add(transcript, 0x36c0)),
                    mload(add(transcript, 0xf80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3700),
                mulmod(
                    mload(add(transcript, 0x3300)),
                    mload(add(transcript, 0x36e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3720),
                addmod(
                    mload(add(transcript, 0x3660)),
                    sub(f_q, mload(add(transcript, 0x3700))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3740),
                mulmod(
                    mload(add(transcript, 0x3720)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3760),
                addmod(
                    mload(add(transcript, 0x35e0)),
                    mload(add(transcript, 0x3740)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3780),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3760)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x37a0),
                addmod(
                    mload(add(transcript, 0xfc0)),
                    sub(f_q, mload(add(transcript, 0x1000))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x37c0),
                mulmod(
                    mload(add(transcript, 0x37a0)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x37e0),
                addmod(
                    mload(add(transcript, 0x3780)),
                    mload(add(transcript, 0x37c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3800),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x37e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3820),
                mulmod(
                    mload(add(transcript, 0x37a0)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3840),
                addmod(
                    mload(add(transcript, 0xfc0)),
                    sub(f_q, mload(add(transcript, 0xfe0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3860),
                mulmod(
                    mload(add(transcript, 0x3840)),
                    mload(add(transcript, 0x3820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3880),
                addmod(
                    mload(add(transcript, 0x3800)),
                    mload(add(transcript, 0x3860)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38a0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38c0),
                addmod(1, sub(f_q, mload(add(transcript, 0x1020))), f_q)
            )
            mstore(
                add(transcript, 0x38e0),
                mulmod(
                    mload(add(transcript, 0x38c0)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3900),
                addmod(
                    mload(add(transcript, 0x38a0)),
                    mload(add(transcript, 0x38e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3920),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3940),
                mulmod(
                    mload(add(transcript, 0x1020)),
                    mload(add(transcript, 0x1020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3960),
                addmod(
                    mload(add(transcript, 0x3940)),
                    sub(f_q, mload(add(transcript, 0x1020))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3980),
                mulmod(
                    mload(add(transcript, 0x3960)),
                    mload(add(transcript, 0x20e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39a0),
                addmod(
                    mload(add(transcript, 0x3920)),
                    mload(add(transcript, 0x3980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39c0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x39a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39e0),
                addmod(
                    mload(add(transcript, 0x1060)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a00),
                mulmod(
                    mload(add(transcript, 0x39e0)),
                    mload(add(transcript, 0x1040)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a20),
                addmod(
                    mload(add(transcript, 0x10a0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a40),
                mulmod(
                    mload(add(transcript, 0x3a20)),
                    mload(add(transcript, 0x3a00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a60),
                mulmod(
                    mload(add(transcript, 0xb20)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a80),
                addmod(
                    mload(add(transcript, 0x3220)),
                    mload(add(transcript, 0x3a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3aa0),
                addmod(
                    mload(add(transcript, 0x3a80)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ac0),
                mulmod(
                    mload(add(transcript, 0x3aa0)),
                    mload(add(transcript, 0x1020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ae0),
                mulmod(
                    mload(add(transcript, 0x3300)),
                    mload(add(transcript, 0x3ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b00),
                addmod(
                    mload(add(transcript, 0x3a40)),
                    sub(f_q, mload(add(transcript, 0x3ae0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b20),
                mulmod(
                    mload(add(transcript, 0x3b00)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b40),
                addmod(
                    mload(add(transcript, 0x39c0)),
                    mload(add(transcript, 0x3b20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b60),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3b40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b80),
                addmod(
                    mload(add(transcript, 0x1060)),
                    sub(f_q, mload(add(transcript, 0x10a0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ba0),
                mulmod(
                    mload(add(transcript, 0x3b80)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3bc0),
                addmod(
                    mload(add(transcript, 0x3b60)),
                    mload(add(transcript, 0x3ba0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3be0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3bc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c00),
                mulmod(
                    mload(add(transcript, 0x3b80)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c20),
                addmod(
                    mload(add(transcript, 0x1060)),
                    sub(f_q, mload(add(transcript, 0x1080))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c40),
                mulmod(
                    mload(add(transcript, 0x3c20)),
                    mload(add(transcript, 0x3c00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c60),
                addmod(
                    mload(add(transcript, 0x3be0)),
                    mload(add(transcript, 0x3c40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c80),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3c60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ca0),
                addmod(1, sub(f_q, mload(add(transcript, 0x10c0))), f_q)
            )
            mstore(
                add(transcript, 0x3cc0),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ce0),
                addmod(
                    mload(add(transcript, 0x3c80)),
                    mload(add(transcript, 0x3cc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d00),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3ce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d20),
                mulmod(
                    mload(add(transcript, 0x10c0)),
                    mload(add(transcript, 0x10c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d40),
                addmod(
                    mload(add(transcript, 0x3d20)),
                    sub(f_q, mload(add(transcript, 0x10c0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d60),
                mulmod(
                    mload(add(transcript, 0x3d40)),
                    mload(add(transcript, 0x20e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d80),
                addmod(
                    mload(add(transcript, 0x3d00)),
                    mload(add(transcript, 0x3d60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3da0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3d80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3dc0),
                addmod(
                    mload(add(transcript, 0x1100)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3de0),
                mulmod(
                    mload(add(transcript, 0x3dc0)),
                    mload(add(transcript, 0x10e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e00),
                addmod(
                    mload(add(transcript, 0x1140)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e20),
                mulmod(
                    mload(add(transcript, 0x3e00)),
                    mload(add(transcript, 0x3de0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e40),
                mulmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e60),
                addmod(
                    mload(add(transcript, 0x3220)),
                    mload(add(transcript, 0x3e40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e80),
                addmod(
                    mload(add(transcript, 0x3e60)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ea0),
                mulmod(
                    mload(add(transcript, 0x3e80)),
                    mload(add(transcript, 0x10c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ec0),
                mulmod(
                    mload(add(transcript, 0x3300)),
                    mload(add(transcript, 0x3ea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ee0),
                addmod(
                    mload(add(transcript, 0x3e20)),
                    sub(f_q, mload(add(transcript, 0x3ec0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f00),
                mulmod(
                    mload(add(transcript, 0x3ee0)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f20),
                addmod(
                    mload(add(transcript, 0x3da0)),
                    mload(add(transcript, 0x3f00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f40),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3f20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f60),
                addmod(
                    mload(add(transcript, 0x1100)),
                    sub(f_q, mload(add(transcript, 0x1140))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f80),
                mulmod(
                    mload(add(transcript, 0x3f60)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3fa0),
                addmod(
                    mload(add(transcript, 0x3f40)),
                    mload(add(transcript, 0x3f80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3fc0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3fa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3fe0),
                mulmod(
                    mload(add(transcript, 0x3f60)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4000),
                addmod(
                    mload(add(transcript, 0x1100)),
                    sub(f_q, mload(add(transcript, 0x1120))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4020),
                mulmod(
                    mload(add(transcript, 0x4000)),
                    mload(add(transcript, 0x3fe0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4040),
                addmod(
                    mload(add(transcript, 0x3fc0)),
                    mload(add(transcript, 0x4020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4060),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x4040)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4080),
                addmod(1, sub(f_q, mload(add(transcript, 0x1160))), f_q)
            )
            mstore(
                add(transcript, 0x40a0),
                mulmod(
                    mload(add(transcript, 0x4080)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x40c0),
                addmod(
                    mload(add(transcript, 0x4060)),
                    mload(add(transcript, 0x40a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x40e0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x40c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4100),
                mulmod(
                    mload(add(transcript, 0x1160)),
                    mload(add(transcript, 0x1160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4120),
                addmod(
                    mload(add(transcript, 0x4100)),
                    sub(f_q, mload(add(transcript, 0x1160))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4140),
                mulmod(
                    mload(add(transcript, 0x4120)),
                    mload(add(transcript, 0x20e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4160),
                addmod(
                    mload(add(transcript, 0x40e0)),
                    mload(add(transcript, 0x4140)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4180),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x4160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x41a0),
                addmod(
                    mload(add(transcript, 0x11a0)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x41c0),
                mulmod(
                    mload(add(transcript, 0x41a0)),
                    mload(add(transcript, 0x1180)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x41e0),
                addmod(
                    mload(add(transcript, 0x11e0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4200),
                mulmod(
                    mload(add(transcript, 0x41e0)),
                    mload(add(transcript, 0x41c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4220),
                mulmod(
                    mload(add(transcript, 0x3a0)),
                    mload(add(transcript, 0xd00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4240),
                mulmod(
                    mload(add(transcript, 0xae0)),
                    mload(add(transcript, 0xd40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4260),
                addmod(
                    mload(add(transcript, 0x4220)),
                    mload(add(transcript, 0x4240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4280),
                addmod(
                    mload(add(transcript, 0x4260)),
                    mload(add(transcript, 0x680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x42a0),
                mulmod(
                    mload(add(transcript, 0x4280)),
                    mload(add(transcript, 0x1160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x42c0),
                mulmod(
                    mload(add(transcript, 0x3300)),
                    mload(add(transcript, 0x42a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x42e0),
                addmod(
                    mload(add(transcript, 0x4200)),
                    sub(f_q, mload(add(transcript, 0x42c0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4300),
                mulmod(
                    mload(add(transcript, 0x42e0)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4320),
                addmod(
                    mload(add(transcript, 0x4180)),
                    mload(add(transcript, 0x4300)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4340),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x4320)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4360),
                addmod(
                    mload(add(transcript, 0x11a0)),
                    sub(f_q, mload(add(transcript, 0x11e0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4380),
                mulmod(
                    mload(add(transcript, 0x4360)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x43a0),
                addmod(
                    mload(add(transcript, 0x4340)),
                    mload(add(transcript, 0x4380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x43c0),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x43a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x43e0),
                mulmod(
                    mload(add(transcript, 0x4360)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4400),
                addmod(
                    mload(add(transcript, 0x11a0)),
                    sub(f_q, mload(add(transcript, 0x11c0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4420),
                mulmod(
                    mload(add(transcript, 0x4400)),
                    mload(add(transcript, 0x43e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4440),
                addmod(
                    mload(add(transcript, 0x43c0)),
                    mload(add(transcript, 0x4420)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4460),
                mulmod(
                    mload(add(transcript, 0x1700)),
                    mload(add(transcript, 0x1700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4480),
                mulmod(
                    mload(add(transcript, 0x4460)),
                    mload(add(transcript, 0x1700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x44a0),
                mulmod(
                    mload(add(transcript, 0x4480)),
                    mload(add(transcript, 0x1700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x44c0),
                mulmod(1, mload(add(transcript, 0x1700)), f_q)
            )
            mstore(
                add(transcript, 0x44e0),
                mulmod(1, mload(add(transcript, 0x4460)), f_q)
            )
            mstore(
                add(transcript, 0x4500),
                mulmod(1, mload(add(transcript, 0x4480)), f_q)
            )
            mstore(
                add(transcript, 0x4520),
                mulmod(
                    mload(add(transcript, 0x4440)),
                    mload(add(transcript, 0x1720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4540),
                mulmod(
                    mload(add(transcript, 0x1380)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4560),
                mulmod(
                    mload(add(transcript, 0x4540)),
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
                    mload(add(transcript, 0x1220)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x45c0),
                mulmod(
                    mload(add(transcript, 0x45a0)),
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
                mulmod(sub(f_q, mload(add(transcript, 0xae0))), 1, f_q)
            )
            mstore(
                add(transcript, 0x4b20),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xb00))),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4b40),
                mulmod(1, mload(add(transcript, 0x1220)), f_q)
            )
            mstore(
                add(transcript, 0x4b60),
                addmod(
                    mload(add(transcript, 0x4b00)),
                    mload(add(transcript, 0x4b20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4b80),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xb20))),
                    mload(add(transcript, 0x45a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ba0),
                mulmod(1, mload(add(transcript, 0x45a0)), f_q)
            )
            mstore(
                add(transcript, 0x4bc0),
                addmod(
                    mload(add(transcript, 0x4b60)),
                    mload(add(transcript, 0x4b80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4be0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xb40))),
                    mload(add(transcript, 0x45c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4c00),
                mulmod(1, mload(add(transcript, 0x45c0)), f_q)
            )
            mstore(
                add(transcript, 0x4c20),
                addmod(
                    mload(add(transcript, 0x4bc0)),
                    mload(add(transcript, 0x4be0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4c40),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xb60))),
                    mload(add(transcript, 0x45e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4c60),
                mulmod(1, mload(add(transcript, 0x45e0)), f_q)
            )
            mstore(
                add(transcript, 0x4c80),
                addmod(
                    mload(add(transcript, 0x4c20)),
                    mload(add(transcript, 0x4c40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ca0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xe40))),
                    mload(add(transcript, 0x4600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4cc0),
                mulmod(1, mload(add(transcript, 0x4600)), f_q)
            )
            mstore(
                add(transcript, 0x4ce0),
                addmod(
                    mload(add(transcript, 0x4c80)),
                    mload(add(transcript, 0x4ca0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4d00),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xea0))),
                    mload(add(transcript, 0x4620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4d20),
                mulmod(1, mload(add(transcript, 0x4620)), f_q)
            )
            mstore(
                add(transcript, 0x4d40),
                addmod(
                    mload(add(transcript, 0x4ce0)),
                    mload(add(transcript, 0x4d00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4d60),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xee0))),
                    mload(add(transcript, 0x4640)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4d80),
                mulmod(1, mload(add(transcript, 0x4640)), f_q)
            )
            mstore(
                add(transcript, 0x4da0),
                addmod(
                    mload(add(transcript, 0x4d40)),
                    mload(add(transcript, 0x4d60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4dc0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xf20))),
                    mload(add(transcript, 0x4660)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4de0),
                mulmod(1, mload(add(transcript, 0x4660)), f_q)
            )
            mstore(
                add(transcript, 0x4e00),
                addmod(
                    mload(add(transcript, 0x4da0)),
                    mload(add(transcript, 0x4dc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4e20),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xf60))),
                    mload(add(transcript, 0x4680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4e40),
                mulmod(1, mload(add(transcript, 0x4680)), f_q)
            )
            mstore(
                add(transcript, 0x4e60),
                addmod(
                    mload(add(transcript, 0x4e00)),
                    mload(add(transcript, 0x4e20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4e80),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xf80))),
                    mload(add(transcript, 0x46a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ea0),
                mulmod(1, mload(add(transcript, 0x46a0)), f_q)
            )
            mstore(
                add(transcript, 0x4ec0),
                addmod(
                    mload(add(transcript, 0x4e60)),
                    mload(add(transcript, 0x4e80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ee0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xfc0))),
                    mload(add(transcript, 0x46c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4f00),
                mulmod(1, mload(add(transcript, 0x46c0)), f_q)
            )
            mstore(
                add(transcript, 0x4f20),
                addmod(
                    mload(add(transcript, 0x4ec0)),
                    mload(add(transcript, 0x4ee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4f40),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1000))),
                    mload(add(transcript, 0x46e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4f60),
                mulmod(1, mload(add(transcript, 0x46e0)), f_q)
            )
            mstore(
                add(transcript, 0x4f80),
                addmod(
                    mload(add(transcript, 0x4f20)),
                    mload(add(transcript, 0x4f40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4fa0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1020))),
                    mload(add(transcript, 0x4700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4fc0),
                mulmod(1, mload(add(transcript, 0x4700)), f_q)
            )
            mstore(
                add(transcript, 0x4fe0),
                addmod(
                    mload(add(transcript, 0x4f80)),
                    mload(add(transcript, 0x4fa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5000),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1060))),
                    mload(add(transcript, 0x4720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5020),
                mulmod(1, mload(add(transcript, 0x4720)), f_q)
            )
            mstore(
                add(transcript, 0x5040),
                addmod(
                    mload(add(transcript, 0x4fe0)),
                    mload(add(transcript, 0x5000)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5060),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x10a0))),
                    mload(add(transcript, 0x4740)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5080),
                mulmod(1, mload(add(transcript, 0x4740)), f_q)
            )
            mstore(
                add(transcript, 0x50a0),
                addmod(
                    mload(add(transcript, 0x5040)),
                    mload(add(transcript, 0x5060)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x50c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x10c0))),
                    mload(add(transcript, 0x4760)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x50e0),
                mulmod(1, mload(add(transcript, 0x4760)), f_q)
            )
            mstore(
                add(transcript, 0x5100),
                addmod(
                    mload(add(transcript, 0x50a0)),
                    mload(add(transcript, 0x50c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5120),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1100))),
                    mload(add(transcript, 0x4780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5140),
                mulmod(1, mload(add(transcript, 0x4780)), f_q)
            )
            mstore(
                add(transcript, 0x5160),
                addmod(
                    mload(add(transcript, 0x5100)),
                    mload(add(transcript, 0x5120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5180),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1140))),
                    mload(add(transcript, 0x47a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x51a0),
                mulmod(1, mload(add(transcript, 0x47a0)), f_q)
            )
            mstore(
                add(transcript, 0x51c0),
                addmod(
                    mload(add(transcript, 0x5160)),
                    mload(add(transcript, 0x5180)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x51e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1160))),
                    mload(add(transcript, 0x47c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5200),
                mulmod(1, mload(add(transcript, 0x47c0)), f_q)
            )
            mstore(
                add(transcript, 0x5220),
                addmod(
                    mload(add(transcript, 0x51c0)),
                    mload(add(transcript, 0x51e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5240),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x11a0))),
                    mload(add(transcript, 0x47e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5260),
                mulmod(1, mload(add(transcript, 0x47e0)), f_q)
            )
            mstore(
                add(transcript, 0x5280),
                addmod(
                    mload(add(transcript, 0x5220)),
                    mload(add(transcript, 0x5240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x52a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x11e0))),
                    mload(add(transcript, 0x4800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x52c0),
                mulmod(1, mload(add(transcript, 0x4800)), f_q)
            )
            mstore(
                add(transcript, 0x52e0),
                addmod(
                    mload(add(transcript, 0x5280)),
                    mload(add(transcript, 0x52a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5300),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xba0))),
                    mload(add(transcript, 0x4820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5320),
                mulmod(1, mload(add(transcript, 0x4820)), f_q)
            )
            mstore(
                add(transcript, 0x5340),
                addmod(
                    mload(add(transcript, 0x52e0)),
                    mload(add(transcript, 0x5300)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5360),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xbc0))),
                    mload(add(transcript, 0x4840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5380),
                mulmod(1, mload(add(transcript, 0x4840)), f_q)
            )
            mstore(
                add(transcript, 0x53a0),
                addmod(
                    mload(add(transcript, 0x5340)),
                    mload(add(transcript, 0x5360)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x53c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xbe0))),
                    mload(add(transcript, 0x4860)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x53e0),
                mulmod(1, mload(add(transcript, 0x4860)), f_q)
            )
            mstore(
                add(transcript, 0x5400),
                addmod(
                    mload(add(transcript, 0x53a0)),
                    mload(add(transcript, 0x53c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5420),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xc00))),
                    mload(add(transcript, 0x4880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5440),
                mulmod(1, mload(add(transcript, 0x4880)), f_q)
            )
            mstore(
                add(transcript, 0x5460),
                addmod(
                    mload(add(transcript, 0x5400)),
                    mload(add(transcript, 0x5420)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5480),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xc20))),
                    mload(add(transcript, 0x48a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x54a0),
                mulmod(1, mload(add(transcript, 0x48a0)), f_q)
            )
            mstore(
                add(transcript, 0x54c0),
                addmod(
                    mload(add(transcript, 0x5460)),
                    mload(add(transcript, 0x5480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x54e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xc40))),
                    mload(add(transcript, 0x48c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5500),
                mulmod(1, mload(add(transcript, 0x48c0)), f_q)
            )
            mstore(
                add(transcript, 0x5520),
                addmod(
                    mload(add(transcript, 0x54c0)),
                    mload(add(transcript, 0x54e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5540),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xc60))),
                    mload(add(transcript, 0x48e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5560),
                mulmod(1, mload(add(transcript, 0x48e0)), f_q)
            )
            mstore(
                add(transcript, 0x5580),
                addmod(
                    mload(add(transcript, 0x5520)),
                    mload(add(transcript, 0x5540)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x55a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xc80))),
                    mload(add(transcript, 0x4900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x55c0),
                mulmod(1, mload(add(transcript, 0x4900)), f_q)
            )
            mstore(
                add(transcript, 0x55e0),
                addmod(
                    mload(add(transcript, 0x5580)),
                    mload(add(transcript, 0x55a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5600),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xca0))),
                    mload(add(transcript, 0x4920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5620),
                mulmod(1, mload(add(transcript, 0x4920)), f_q)
            )
            mstore(
                add(transcript, 0x5640),
                addmod(
                    mload(add(transcript, 0x55e0)),
                    mload(add(transcript, 0x5600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5660),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xcc0))),
                    mload(add(transcript, 0x4940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5680),
                mulmod(1, mload(add(transcript, 0x4940)), f_q)
            )
            mstore(
                add(transcript, 0x56a0),
                addmod(
                    mload(add(transcript, 0x5640)),
                    mload(add(transcript, 0x5660)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x56c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xce0))),
                    mload(add(transcript, 0x4960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x56e0),
                mulmod(1, mload(add(transcript, 0x4960)), f_q)
            )
            mstore(
                add(transcript, 0x5700),
                addmod(
                    mload(add(transcript, 0x56a0)),
                    mload(add(transcript, 0x56c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5720),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xd00))),
                    mload(add(transcript, 0x4980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5740),
                mulmod(1, mload(add(transcript, 0x4980)), f_q)
            )
            mstore(
                add(transcript, 0x5760),
                addmod(
                    mload(add(transcript, 0x5700)),
                    mload(add(transcript, 0x5720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5780),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xd20))),
                    mload(add(transcript, 0x49a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x57a0),
                mulmod(1, mload(add(transcript, 0x49a0)), f_q)
            )
            mstore(
                add(transcript, 0x57c0),
                addmod(
                    mload(add(transcript, 0x5760)),
                    mload(add(transcript, 0x5780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x57e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xd40))),
                    mload(add(transcript, 0x49c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5800),
                mulmod(1, mload(add(transcript, 0x49c0)), f_q)
            )
            mstore(
                add(transcript, 0x5820),
                addmod(
                    mload(add(transcript, 0x57c0)),
                    mload(add(transcript, 0x57e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5840),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xd80))),
                    mload(add(transcript, 0x49e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5860),
                mulmod(1, mload(add(transcript, 0x49e0)), f_q)
            )
            mstore(
                add(transcript, 0x5880),
                addmod(
                    mload(add(transcript, 0x5820)),
                    mload(add(transcript, 0x5840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x58a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xda0))),
                    mload(add(transcript, 0x4a00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x58c0),
                mulmod(1, mload(add(transcript, 0x4a00)), f_q)
            )
            mstore(
                add(transcript, 0x58e0),
                addmod(
                    mload(add(transcript, 0x5880)),
                    mload(add(transcript, 0x58a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5900),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xdc0))),
                    mload(add(transcript, 0x4a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5920),
                mulmod(1, mload(add(transcript, 0x4a20)), f_q)
            )
            mstore(
                add(transcript, 0x5940),
                addmod(
                    mload(add(transcript, 0x58e0)),
                    mload(add(transcript, 0x5900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5960),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xde0))),
                    mload(add(transcript, 0x4a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5980),
                mulmod(1, mload(add(transcript, 0x4a40)), f_q)
            )
            mstore(
                add(transcript, 0x59a0),
                addmod(
                    mload(add(transcript, 0x5940)),
                    mload(add(transcript, 0x5960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x59c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xe00))),
                    mload(add(transcript, 0x4a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x59e0),
                mulmod(1, mload(add(transcript, 0x4a60)), f_q)
            )
            mstore(
                add(transcript, 0x5a00),
                addmod(
                    mload(add(transcript, 0x59a0)),
                    mload(add(transcript, 0x59c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5a20),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xe20))),
                    mload(add(transcript, 0x4a80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5a40),
                mulmod(1, mload(add(transcript, 0x4a80)), f_q)
            )
            mstore(
                add(transcript, 0x5a60),
                addmod(
                    mload(add(transcript, 0x5a00)),
                    mload(add(transcript, 0x5a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5a80),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x4520))),
                    mload(add(transcript, 0x4aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5aa0),
                mulmod(1, mload(add(transcript, 0x4aa0)), f_q)
            )
            mstore(
                add(transcript, 0x5ac0),
                mulmod(
                    mload(add(transcript, 0x44c0)),
                    mload(add(transcript, 0x4aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5ae0),
                mulmod(
                    mload(add(transcript, 0x44e0)),
                    mload(add(transcript, 0x4aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5b00),
                mulmod(
                    mload(add(transcript, 0x4500)),
                    mload(add(transcript, 0x4aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5b20),
                addmod(
                    mload(add(transcript, 0x5a60)),
                    mload(add(transcript, 0x5a80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5b40),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xd60))),
                    mload(add(transcript, 0x4ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5b60),
                mulmod(1, mload(add(transcript, 0x4ac0)), f_q)
            )
            mstore(
                add(transcript, 0x5b80),
                addmod(
                    mload(add(transcript, 0x5b20)),
                    mload(add(transcript, 0x5b40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x5ba0),
                mulmod(mload(add(transcript, 0x5b80)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5bc0),
                mulmod(mload(add(transcript, 0x4b40)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5be0),
                mulmod(mload(add(transcript, 0x4ba0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5c00),
                mulmod(mload(add(transcript, 0x4c00)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5c20),
                mulmod(mload(add(transcript, 0x4c60)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5c40),
                mulmod(mload(add(transcript, 0x4cc0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5c60),
                mulmod(mload(add(transcript, 0x4d20)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5c80),
                mulmod(mload(add(transcript, 0x4d80)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5ca0),
                mulmod(mload(add(transcript, 0x4de0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5cc0),
                mulmod(mload(add(transcript, 0x4e40)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5ce0),
                mulmod(mload(add(transcript, 0x4ea0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5d00),
                mulmod(mload(add(transcript, 0x4f00)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5d20),
                mulmod(mload(add(transcript, 0x4f60)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5d40),
                mulmod(mload(add(transcript, 0x4fc0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5d60),
                mulmod(mload(add(transcript, 0x5020)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5d80),
                mulmod(mload(add(transcript, 0x5080)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5da0),
                mulmod(mload(add(transcript, 0x50e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5dc0),
                mulmod(mload(add(transcript, 0x5140)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5de0),
                mulmod(mload(add(transcript, 0x51a0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5e00),
                mulmod(mload(add(transcript, 0x5200)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5e20),
                mulmod(mload(add(transcript, 0x5260)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5e40),
                mulmod(mload(add(transcript, 0x52c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5e60),
                mulmod(mload(add(transcript, 0x5320)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5e80),
                mulmod(mload(add(transcript, 0x5380)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5ea0),
                mulmod(mload(add(transcript, 0x53e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5ec0),
                mulmod(mload(add(transcript, 0x5440)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5ee0),
                mulmod(mload(add(transcript, 0x54a0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5f00),
                mulmod(mload(add(transcript, 0x5500)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5f20),
                mulmod(mload(add(transcript, 0x5560)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5f40),
                mulmod(mload(add(transcript, 0x55c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5f60),
                mulmod(mload(add(transcript, 0x5620)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5f80),
                mulmod(mload(add(transcript, 0x5680)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5fa0),
                mulmod(mload(add(transcript, 0x56e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5fc0),
                mulmod(mload(add(transcript, 0x5740)), 1, f_q)
            )
            mstore(
                add(transcript, 0x5fe0),
                mulmod(mload(add(transcript, 0x57a0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6000),
                mulmod(mload(add(transcript, 0x5800)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6020),
                mulmod(mload(add(transcript, 0x5860)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6040),
                mulmod(mload(add(transcript, 0x58c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6060),
                mulmod(mload(add(transcript, 0x5920)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6080),
                mulmod(mload(add(transcript, 0x5980)), 1, f_q)
            )
            mstore(
                add(transcript, 0x60a0),
                mulmod(mload(add(transcript, 0x59e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x60c0),
                mulmod(mload(add(transcript, 0x5a40)), 1, f_q)
            )
            mstore(
                add(transcript, 0x60e0),
                mulmod(mload(add(transcript, 0x5aa0)), 1, f_q)
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
                mulmod(mload(add(transcript, 0x5b60)), 1, f_q)
            )
            mstore(
                add(transcript, 0x6180),
                mulmod(sub(f_q, mload(add(transcript, 0xb80))), 1, f_q)
            )
            mstore(
                add(transcript, 0x61a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xe60))),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x61c0),
                addmod(
                    mload(add(transcript, 0x6180)),
                    mload(add(transcript, 0x61a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x61e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xec0))),
                    mload(add(transcript, 0x45a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6200),
                addmod(
                    mload(add(transcript, 0x61c0)),
                    mload(add(transcript, 0x61e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6220),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xf00))),
                    mload(add(transcript, 0x45c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6240),
                addmod(
                    mload(add(transcript, 0x6200)),
                    mload(add(transcript, 0x6220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6260),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xfa0))),
                    mload(add(transcript, 0x45e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6280),
                addmod(
                    mload(add(transcript, 0x6240)),
                    mload(add(transcript, 0x6260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x62a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1040))),
                    mload(add(transcript, 0x4600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x62c0),
                addmod(
                    mload(add(transcript, 0x6280)),
                    mload(add(transcript, 0x62a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x62e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x10e0))),
                    mload(add(transcript, 0x4620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6300),
                addmod(
                    mload(add(transcript, 0x62c0)),
                    mload(add(transcript, 0x62e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6320),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1180))),
                    mload(add(transcript, 0x4640)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6340),
                addmod(
                    mload(add(transcript, 0x6300)),
                    mload(add(transcript, 0x6320)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6360),
                mulmod(
                    mload(add(transcript, 0x6340)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6380),
                mulmod(1, mload(add(transcript, 0x1380)), f_q)
            )
            mstore(
                add(transcript, 0x63a0),
                mulmod(
                    mload(add(transcript, 0x4b40)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x63c0),
                mulmod(
                    mload(add(transcript, 0x4ba0)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x63e0),
                mulmod(
                    mload(add(transcript, 0x4c00)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6400),
                mulmod(
                    mload(add(transcript, 0x4c60)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6420),
                mulmod(
                    mload(add(transcript, 0x4cc0)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6440),
                mulmod(
                    mload(add(transcript, 0x4d20)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6460),
                mulmod(
                    mload(add(transcript, 0x4d80)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6480),
                addmod(
                    mload(add(transcript, 0x5ba0)),
                    mload(add(transcript, 0x6360)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x64a0),
                addmod(
                    mload(add(transcript, 0x5c20)),
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
                    mload(add(transcript, 0x5ce0)),
                    mload(add(transcript, 0x6400)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6540),
                addmod(
                    mload(add(transcript, 0x5d40)),
                    mload(add(transcript, 0x6420)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6560),
                addmod(
                    mload(add(transcript, 0x5da0)),
                    mload(add(transcript, 0x6440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6580),
                addmod(
                    mload(add(transcript, 0x5e00)),
                    mload(add(transcript, 0x6460)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x65a0),
                mulmod(sub(f_q, mload(add(transcript, 0xe80))), 1, f_q)
            )
            mstore(
                add(transcript, 0x65c0),
                mulmod(
                    mload(add(transcript, 0x65a0)),
                    mload(add(transcript, 0x4540)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x65e0),
                mulmod(1, mload(add(transcript, 0x4540)), f_q)
            )
            mstore(
                add(transcript, 0x6600),
                addmod(
                    mload(add(transcript, 0x6480)),
                    mload(add(transcript, 0x65c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6620),
                addmod(
                    mload(add(transcript, 0x64c0)),
                    mload(add(transcript, 0x65e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6640),
                mulmod(sub(f_q, mload(add(transcript, 0xf40))), 1, f_q)
            )
            mstore(
                add(transcript, 0x6660),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xfe0))),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6680),
                addmod(
                    mload(add(transcript, 0x6640)),
                    mload(add(transcript, 0x6660)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x66a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1080))),
                    mload(add(transcript, 0x45a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x66c0),
                addmod(
                    mload(add(transcript, 0x6680)),
                    mload(add(transcript, 0x66a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x66e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1120))),
                    mload(add(transcript, 0x45c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6700),
                addmod(
                    mload(add(transcript, 0x66c0)),
                    mload(add(transcript, 0x66e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6720),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x11c0))),
                    mload(add(transcript, 0x45e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6740),
                addmod(
                    mload(add(transcript, 0x6700)),
                    mload(add(transcript, 0x6720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6760),
                mulmod(
                    mload(add(transcript, 0x6740)),
                    mload(add(transcript, 0x4560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6780),
                mulmod(1, mload(add(transcript, 0x4560)), f_q)
            )
            mstore(
                add(transcript, 0x67a0),
                mulmod(
                    mload(add(transcript, 0x4b40)),
                    mload(add(transcript, 0x4560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x67c0),
                mulmod(
                    mload(add(transcript, 0x4ba0)),
                    mload(add(transcript, 0x4560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x67e0),
                mulmod(
                    mload(add(transcript, 0x4c00)),
                    mload(add(transcript, 0x4560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6800),
                mulmod(
                    mload(add(transcript, 0x4c60)),
                    mload(add(transcript, 0x4560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6820),
                addmod(
                    mload(add(transcript, 0x6600)),
                    mload(add(transcript, 0x6760)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6840),
                addmod(
                    mload(add(transcript, 0x5ca0)),
                    mload(add(transcript, 0x6780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6860),
                addmod(
                    mload(add(transcript, 0x5d00)),
                    mload(add(transcript, 0x67a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6880),
                addmod(
                    mload(add(transcript, 0x5d60)),
                    mload(add(transcript, 0x67c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x68a0),
                addmod(
                    mload(add(transcript, 0x5dc0)),
                    mload(add(transcript, 0x67e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x68c0),
                addmod(
                    mload(add(transcript, 0x5e20)),
                    mload(add(transcript, 0x6800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x68e0),
                mulmod(1, mload(add(transcript, 0xaa0)), f_q)
            )
            mstore(
                add(transcript, 0x6900),
                mulmod(1, mload(add(transcript, 0x68e0)), f_q)
            )
            mstore(
                add(transcript, 0x6920),
                mulmod(
                    8374374965308410102411073611984011876711565317741801500439755773472076597347,
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6940),
                mulmod(
                    mload(add(transcript, 0x6380)),
                    mload(add(transcript, 0x6920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6960),
                mulmod(
                    21710372849001950800533397158415938114909991150039389063546734567764856596059,
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6980),
                mulmod(
                    mload(add(transcript, 0x65e0)),
                    mload(add(transcript, 0x6960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x69a0),
                mulmod(
                    9741553891420464328295280489650144566903017206473301385034033384879943874347,
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x69c0),
                mulmod(
                    mload(add(transcript, 0x6780)),
                    mload(add(transcript, 0x69a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x69e0),
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            mstore(
                add(transcript, 0x6a00),
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            mstore(add(transcript, 0x6a20), mload(add(transcript, 0x6820)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x69e0),
                        0x60,
                        add(transcript, 0x69e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6a40), mload(add(transcript, 0x69e0)))
            mstore(add(transcript, 0x6a60), mload(add(transcript, 0x6a00)))
            mstore(add(transcript, 0x6a80), mload(add(transcript, 0x240)))
            mstore(add(transcript, 0x6aa0), mload(add(transcript, 0x260)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6a40),
                        0x80,
                        add(transcript, 0x6a40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6ac0), mload(add(transcript, 0x280)))
            mstore(add(transcript, 0x6ae0), mload(add(transcript, 0x2a0)))
            mstore(add(transcript, 0x6b00), mload(add(transcript, 0x5bc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6ac0),
                        0x60,
                        add(transcript, 0x6ac0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6b20), mload(add(transcript, 0x6a40)))
            mstore(add(transcript, 0x6b40), mload(add(transcript, 0x6a60)))
            mstore(add(transcript, 0x6b60), mload(add(transcript, 0x6ac0)))
            mstore(add(transcript, 0x6b80), mload(add(transcript, 0x6ae0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6b20),
                        0x80,
                        add(transcript, 0x6b20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6ba0), mload(add(transcript, 0x2c0)))
            mstore(add(transcript, 0x6bc0), mload(add(transcript, 0x2e0)))
            mstore(add(transcript, 0x6be0), mload(add(transcript, 0x5be0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6ba0),
                        0x60,
                        add(transcript, 0x6ba0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6c00), mload(add(transcript, 0x6b20)))
            mstore(add(transcript, 0x6c20), mload(add(transcript, 0x6b40)))
            mstore(add(transcript, 0x6c40), mload(add(transcript, 0x6ba0)))
            mstore(add(transcript, 0x6c60), mload(add(transcript, 0x6bc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6c00),
                        0x80,
                        add(transcript, 0x6c00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6c80), mload(add(transcript, 0x300)))
            mstore(add(transcript, 0x6ca0), mload(add(transcript, 0x320)))
            mstore(add(transcript, 0x6cc0), mload(add(transcript, 0x5c00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6c80),
                        0x60,
                        add(transcript, 0x6c80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6ce0), mload(add(transcript, 0x6c00)))
            mstore(add(transcript, 0x6d00), mload(add(transcript, 0x6c20)))
            mstore(add(transcript, 0x6d20), mload(add(transcript, 0x6c80)))
            mstore(add(transcript, 0x6d40), mload(add(transcript, 0x6ca0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6ce0),
                        0x80,
                        add(transcript, 0x6ce0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6d60), mload(add(transcript, 0x340)))
            mstore(add(transcript, 0x6d80), mload(add(transcript, 0x360)))
            mstore(add(transcript, 0x6da0), mload(add(transcript, 0x64a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6d60),
                        0x60,
                        add(transcript, 0x6d60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6dc0), mload(add(transcript, 0x6ce0)))
            mstore(add(transcript, 0x6de0), mload(add(transcript, 0x6d00)))
            mstore(add(transcript, 0x6e00), mload(add(transcript, 0x6d60)))
            mstore(add(transcript, 0x6e20), mload(add(transcript, 0x6d80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6dc0),
                        0x80,
                        add(transcript, 0x6dc0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6e40), mload(add(transcript, 0x720)))
            mstore(add(transcript, 0x6e60), mload(add(transcript, 0x740)))
            mstore(add(transcript, 0x6e80), mload(add(transcript, 0x6620)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6e40),
                        0x60,
                        add(transcript, 0x6e40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6ea0), mload(add(transcript, 0x6dc0)))
            mstore(add(transcript, 0x6ec0), mload(add(transcript, 0x6de0)))
            mstore(add(transcript, 0x6ee0), mload(add(transcript, 0x6e40)))
            mstore(add(transcript, 0x6f00), mload(add(transcript, 0x6e60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6ea0),
                        0x80,
                        add(transcript, 0x6ea0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6f20), mload(add(transcript, 0x760)))
            mstore(add(transcript, 0x6f40), mload(add(transcript, 0x780)))
            mstore(add(transcript, 0x6f60), mload(add(transcript, 0x64e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6f20),
                        0x60,
                        add(transcript, 0x6f20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6f80), mload(add(transcript, 0x6ea0)))
            mstore(add(transcript, 0x6fa0), mload(add(transcript, 0x6ec0)))
            mstore(add(transcript, 0x6fc0), mload(add(transcript, 0x6f20)))
            mstore(add(transcript, 0x6fe0), mload(add(transcript, 0x6f40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6f80),
                        0x80,
                        add(transcript, 0x6f80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7000), mload(add(transcript, 0x7a0)))
            mstore(add(transcript, 0x7020), mload(add(transcript, 0x7c0)))
            mstore(add(transcript, 0x7040), mload(add(transcript, 0x6500)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7000),
                        0x60,
                        add(transcript, 0x7000),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7060), mload(add(transcript, 0x6f80)))
            mstore(add(transcript, 0x7080), mload(add(transcript, 0x6fa0)))
            mstore(add(transcript, 0x70a0), mload(add(transcript, 0x7000)))
            mstore(add(transcript, 0x70c0), mload(add(transcript, 0x7020)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7060),
                        0x80,
                        add(transcript, 0x7060),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x70e0), mload(add(transcript, 0x3e0)))
            mstore(add(transcript, 0x7100), mload(add(transcript, 0x400)))
            mstore(add(transcript, 0x7120), mload(add(transcript, 0x6840)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x70e0),
                        0x60,
                        add(transcript, 0x70e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7140), mload(add(transcript, 0x7060)))
            mstore(add(transcript, 0x7160), mload(add(transcript, 0x7080)))
            mstore(add(transcript, 0x7180), mload(add(transcript, 0x70e0)))
            mstore(add(transcript, 0x71a0), mload(add(transcript, 0x7100)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7140),
                        0x80,
                        add(transcript, 0x7140),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x71c0), mload(add(transcript, 0x420)))
            mstore(add(transcript, 0x71e0), mload(add(transcript, 0x440)))
            mstore(add(transcript, 0x7200), mload(add(transcript, 0x5cc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x71c0),
                        0x60,
                        add(transcript, 0x71c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7220), mload(add(transcript, 0x7140)))
            mstore(add(transcript, 0x7240), mload(add(transcript, 0x7160)))
            mstore(add(transcript, 0x7260), mload(add(transcript, 0x71c0)))
            mstore(add(transcript, 0x7280), mload(add(transcript, 0x71e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7220),
                        0x80,
                        add(transcript, 0x7220),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x72a0), mload(add(transcript, 0x7e0)))
            mstore(add(transcript, 0x72c0), mload(add(transcript, 0x800)))
            mstore(add(transcript, 0x72e0), mload(add(transcript, 0x6520)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x72a0),
                        0x60,
                        add(transcript, 0x72a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7300), mload(add(transcript, 0x7220)))
            mstore(add(transcript, 0x7320), mload(add(transcript, 0x7240)))
            mstore(add(transcript, 0x7340), mload(add(transcript, 0x72a0)))
            mstore(add(transcript, 0x7360), mload(add(transcript, 0x72c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7300),
                        0x80,
                        add(transcript, 0x7300),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7380), mload(add(transcript, 0x460)))
            mstore(add(transcript, 0x73a0), mload(add(transcript, 0x480)))
            mstore(add(transcript, 0x73c0), mload(add(transcript, 0x6860)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7380),
                        0x60,
                        add(transcript, 0x7380),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x73e0), mload(add(transcript, 0x7300)))
            mstore(add(transcript, 0x7400), mload(add(transcript, 0x7320)))
            mstore(add(transcript, 0x7420), mload(add(transcript, 0x7380)))
            mstore(add(transcript, 0x7440), mload(add(transcript, 0x73a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x73e0),
                        0x80,
                        add(transcript, 0x73e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7460), mload(add(transcript, 0x4a0)))
            mstore(add(transcript, 0x7480), mload(add(transcript, 0x4c0)))
            mstore(add(transcript, 0x74a0), mload(add(transcript, 0x5d20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7460),
                        0x60,
                        add(transcript, 0x7460),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x74c0), mload(add(transcript, 0x73e0)))
            mstore(add(transcript, 0x74e0), mload(add(transcript, 0x7400)))
            mstore(add(transcript, 0x7500), mload(add(transcript, 0x7460)))
            mstore(add(transcript, 0x7520), mload(add(transcript, 0x7480)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x74c0),
                        0x80,
                        add(transcript, 0x74c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7540), mload(add(transcript, 0x820)))
            mstore(add(transcript, 0x7560), mload(add(transcript, 0x840)))
            mstore(add(transcript, 0x7580), mload(add(transcript, 0x6540)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7540),
                        0x60,
                        add(transcript, 0x7540),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x75a0), mload(add(transcript, 0x74c0)))
            mstore(add(transcript, 0x75c0), mload(add(transcript, 0x74e0)))
            mstore(add(transcript, 0x75e0), mload(add(transcript, 0x7540)))
            mstore(add(transcript, 0x7600), mload(add(transcript, 0x7560)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x75a0),
                        0x80,
                        add(transcript, 0x75a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7620), mload(add(transcript, 0x4e0)))
            mstore(add(transcript, 0x7640), mload(add(transcript, 0x500)))
            mstore(add(transcript, 0x7660), mload(add(transcript, 0x6880)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7620),
                        0x60,
                        add(transcript, 0x7620),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7680), mload(add(transcript, 0x75a0)))
            mstore(add(transcript, 0x76a0), mload(add(transcript, 0x75c0)))
            mstore(add(transcript, 0x76c0), mload(add(transcript, 0x7620)))
            mstore(add(transcript, 0x76e0), mload(add(transcript, 0x7640)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7680),
                        0x80,
                        add(transcript, 0x7680),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7700), mload(add(transcript, 0x520)))
            mstore(add(transcript, 0x7720), mload(add(transcript, 0x540)))
            mstore(add(transcript, 0x7740), mload(add(transcript, 0x5d80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7700),
                        0x60,
                        add(transcript, 0x7700),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7760), mload(add(transcript, 0x7680)))
            mstore(add(transcript, 0x7780), mload(add(transcript, 0x76a0)))
            mstore(add(transcript, 0x77a0), mload(add(transcript, 0x7700)))
            mstore(add(transcript, 0x77c0), mload(add(transcript, 0x7720)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7760),
                        0x80,
                        add(transcript, 0x7760),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x77e0), mload(add(transcript, 0x860)))
            mstore(add(transcript, 0x7800), mload(add(transcript, 0x880)))
            mstore(add(transcript, 0x7820), mload(add(transcript, 0x6560)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x77e0),
                        0x60,
                        add(transcript, 0x77e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7840), mload(add(transcript, 0x7760)))
            mstore(add(transcript, 0x7860), mload(add(transcript, 0x7780)))
            mstore(add(transcript, 0x7880), mload(add(transcript, 0x77e0)))
            mstore(add(transcript, 0x78a0), mload(add(transcript, 0x7800)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7840),
                        0x80,
                        add(transcript, 0x7840),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x78c0), mload(add(transcript, 0x560)))
            mstore(add(transcript, 0x78e0), mload(add(transcript, 0x580)))
            mstore(add(transcript, 0x7900), mload(add(transcript, 0x68a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x78c0),
                        0x60,
                        add(transcript, 0x78c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7920), mload(add(transcript, 0x7840)))
            mstore(add(transcript, 0x7940), mload(add(transcript, 0x7860)))
            mstore(add(transcript, 0x7960), mload(add(transcript, 0x78c0)))
            mstore(add(transcript, 0x7980), mload(add(transcript, 0x78e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7920),
                        0x80,
                        add(transcript, 0x7920),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x79a0), mload(add(transcript, 0x5a0)))
            mstore(add(transcript, 0x79c0), mload(add(transcript, 0x5c0)))
            mstore(add(transcript, 0x79e0), mload(add(transcript, 0x5de0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x79a0),
                        0x60,
                        add(transcript, 0x79a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7a00), mload(add(transcript, 0x7920)))
            mstore(add(transcript, 0x7a20), mload(add(transcript, 0x7940)))
            mstore(add(transcript, 0x7a40), mload(add(transcript, 0x79a0)))
            mstore(add(transcript, 0x7a60), mload(add(transcript, 0x79c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7a00),
                        0x80,
                        add(transcript, 0x7a00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7a80), mload(add(transcript, 0x8a0)))
            mstore(add(transcript, 0x7aa0), mload(add(transcript, 0x8c0)))
            mstore(add(transcript, 0x7ac0), mload(add(transcript, 0x6580)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7a80),
                        0x60,
                        add(transcript, 0x7a80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7ae0), mload(add(transcript, 0x7a00)))
            mstore(add(transcript, 0x7b00), mload(add(transcript, 0x7a20)))
            mstore(add(transcript, 0x7b20), mload(add(transcript, 0x7a80)))
            mstore(add(transcript, 0x7b40), mload(add(transcript, 0x7aa0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7ae0),
                        0x80,
                        add(transcript, 0x7ae0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7b60), mload(add(transcript, 0x5e0)))
            mstore(add(transcript, 0x7b80), mload(add(transcript, 0x600)))
            mstore(add(transcript, 0x7ba0), mload(add(transcript, 0x68c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7b60),
                        0x60,
                        add(transcript, 0x7b60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7bc0), mload(add(transcript, 0x7ae0)))
            mstore(add(transcript, 0x7be0), mload(add(transcript, 0x7b00)))
            mstore(add(transcript, 0x7c00), mload(add(transcript, 0x7b60)))
            mstore(add(transcript, 0x7c20), mload(add(transcript, 0x7b80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7bc0),
                        0x80,
                        add(transcript, 0x7bc0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7c40), mload(add(transcript, 0x620)))
            mstore(add(transcript, 0x7c60), mload(add(transcript, 0x640)))
            mstore(add(transcript, 0x7c80), mload(add(transcript, 0x5e40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7c40),
                        0x60,
                        add(transcript, 0x7c40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7ca0), mload(add(transcript, 0x7bc0)))
            mstore(add(transcript, 0x7cc0), mload(add(transcript, 0x7be0)))
            mstore(add(transcript, 0x7ce0), mload(add(transcript, 0x7c40)))
            mstore(add(transcript, 0x7d00), mload(add(transcript, 0x7c60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7ca0),
                        0x80,
                        add(transcript, 0x7ca0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x7d20),
                0x14bee3078b76352eabfad2927c1a804f1f4fbeeacfc4af9ff493739d38681059
            )
            mstore(
                add(transcript, 0x7d40),
                0x25c3aa3ad5920ebdb233a36d799da487bd4b61fa606035fd23eed88d6cdf4b3f
            )
            mstore(add(transcript, 0x7d60), mload(add(transcript, 0x5e60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7d20),
                        0x60,
                        add(transcript, 0x7d20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7d80), mload(add(transcript, 0x7ca0)))
            mstore(add(transcript, 0x7da0), mload(add(transcript, 0x7cc0)))
            mstore(add(transcript, 0x7dc0), mload(add(transcript, 0x7d20)))
            mstore(add(transcript, 0x7de0), mload(add(transcript, 0x7d40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7d80),
                        0x80,
                        add(transcript, 0x7d80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x7e00),
                0x16c23762275112abc831ff7735375645cc203e9a6b154503e695b88d6b586e3a
            )
            mstore(
                add(transcript, 0x7e20),
                0x1611f752ce7e2e49526e79415082f2aa630be99f9c477d1533d8f92e80fd0258
            )
            mstore(add(transcript, 0x7e40), mload(add(transcript, 0x5e80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7e00),
                        0x60,
                        add(transcript, 0x7e00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7e60), mload(add(transcript, 0x7d80)))
            mstore(add(transcript, 0x7e80), mload(add(transcript, 0x7da0)))
            mstore(add(transcript, 0x7ea0), mload(add(transcript, 0x7e00)))
            mstore(add(transcript, 0x7ec0), mload(add(transcript, 0x7e20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7e60),
                        0x80,
                        add(transcript, 0x7e60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x7ee0),
                0x16295f7e4e83aaae2ff37f5b8c90da09f324bfa62b1c4eeb508f6e53ca1b3f99
            )
            mstore(
                add(transcript, 0x7f00),
                0x1e1f633905edbc767d9cbfa5cbe508fefce3461942cf87616f1a2eed4ff2a54b
            )
            mstore(add(transcript, 0x7f20), mload(add(transcript, 0x5ea0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7ee0),
                        0x60,
                        add(transcript, 0x7ee0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x7f40), mload(add(transcript, 0x7e60)))
            mstore(add(transcript, 0x7f60), mload(add(transcript, 0x7e80)))
            mstore(add(transcript, 0x7f80), mload(add(transcript, 0x7ee0)))
            mstore(add(transcript, 0x7fa0), mload(add(transcript, 0x7f00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x7f40),
                        0x80,
                        add(transcript, 0x7f40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x7fc0),
                0x26dc080099c3e3f8fceacd3e37588658bdbda1f9f8448afc95a718a100aa963d
            )
            mstore(
                add(transcript, 0x7fe0),
                0x29ed758a06a4d2d64e3f899adcbf440fb480757e1eb51d35e98d12b997ebc1a3
            )
            mstore(add(transcript, 0x8000), mload(add(transcript, 0x5ec0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x7fc0),
                        0x60,
                        add(transcript, 0x7fc0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8020), mload(add(transcript, 0x7f40)))
            mstore(add(transcript, 0x8040), mload(add(transcript, 0x7f60)))
            mstore(add(transcript, 0x8060), mload(add(transcript, 0x7fc0)))
            mstore(add(transcript, 0x8080), mload(add(transcript, 0x7fe0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8020),
                        0x80,
                        add(transcript, 0x8020),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x80a0),
                0x14235922221daf1da0d8ffeeee7b412d75db961767c0249153a4c979b21bc988
            )
            mstore(
                add(transcript, 0x80c0),
                0x20b164ad09b6bd6d6c02fd901c269693d45ea261ce8360a6f54a5a903f4a12e4
            )
            mstore(add(transcript, 0x80e0), mload(add(transcript, 0x5ee0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x80a0),
                        0x60,
                        add(transcript, 0x80a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8100), mload(add(transcript, 0x8020)))
            mstore(add(transcript, 0x8120), mload(add(transcript, 0x8040)))
            mstore(add(transcript, 0x8140), mload(add(transcript, 0x80a0)))
            mstore(add(transcript, 0x8160), mload(add(transcript, 0x80c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8100),
                        0x80,
                        add(transcript, 0x8100),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8180),
                0x029a646c2258d0a6ab05217ee1dd43d7f0e16c2b0b861bf962939dfd8b34fbe1
            )
            mstore(
                add(transcript, 0x81a0),
                0x287da2091440bea371562ce403846bc9e1f63d11dd0d9a248e893a11cc74bff3
            )
            mstore(add(transcript, 0x81c0), mload(add(transcript, 0x5f00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8180),
                        0x60,
                        add(transcript, 0x8180),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x81e0), mload(add(transcript, 0x8100)))
            mstore(add(transcript, 0x8200), mload(add(transcript, 0x8120)))
            mstore(add(transcript, 0x8220), mload(add(transcript, 0x8180)))
            mstore(add(transcript, 0x8240), mload(add(transcript, 0x81a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x81e0),
                        0x80,
                        add(transcript, 0x81e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8260),
                0x1f012f76d6cf4792a3cb77dc30f93039f6798d60ecd6887711eed9b19a2fb26d
            )
            mstore(
                add(transcript, 0x8280),
                0x18ade39c61bc98da53bf8442acb520e75ba1f534dffce6d16634c8554a342a05
            )
            mstore(add(transcript, 0x82a0), mload(add(transcript, 0x5f20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8260),
                        0x60,
                        add(transcript, 0x8260),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x82c0), mload(add(transcript, 0x81e0)))
            mstore(add(transcript, 0x82e0), mload(add(transcript, 0x8200)))
            mstore(add(transcript, 0x8300), mload(add(transcript, 0x8260)))
            mstore(add(transcript, 0x8320), mload(add(transcript, 0x8280)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x82c0),
                        0x80,
                        add(transcript, 0x82c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8340),
                0x2b0f9c91116258809dca26355c4e6d58a73c7b3231961a66110eea1b735048ec
            )
            mstore(
                add(transcript, 0x8360),
                0x20cfe63fed42ba40e706248e1152eaecea0d4793b75b61c775cde86e90cddee9
            )
            mstore(add(transcript, 0x8380), mload(add(transcript, 0x5f40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8340),
                        0x60,
                        add(transcript, 0x8340),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x83a0), mload(add(transcript, 0x82c0)))
            mstore(add(transcript, 0x83c0), mload(add(transcript, 0x82e0)))
            mstore(add(transcript, 0x83e0), mload(add(transcript, 0x8340)))
            mstore(add(transcript, 0x8400), mload(add(transcript, 0x8360)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x83a0),
                        0x80,
                        add(transcript, 0x83a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8420),
                0x0d629663b391bbc7d24ac11e898d92e5b455d8f4974f2414372b1aa8ae425b8a
            )
            mstore(
                add(transcript, 0x8440),
                0x03797bd5e44d313dfb7a8c7eb24f06d2a4707ecc34031664f51fa3d22d419948
            )
            mstore(add(transcript, 0x8460), mload(add(transcript, 0x5f60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8420),
                        0x60,
                        add(transcript, 0x8420),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8480), mload(add(transcript, 0x83a0)))
            mstore(add(transcript, 0x84a0), mload(add(transcript, 0x83c0)))
            mstore(add(transcript, 0x84c0), mload(add(transcript, 0x8420)))
            mstore(add(transcript, 0x84e0), mload(add(transcript, 0x8440)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8480),
                        0x80,
                        add(transcript, 0x8480),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8500),
                0x0944f013d3bf911f8a9051da1f8f7515637fec6111ddcb625f38937be185208e
            )
            mstore(
                add(transcript, 0x8520),
                0x2a3662efaac67cef3262a9943ef0810b6307d7a8c55e7da2d31bcc5cd5c59c7d
            )
            mstore(add(transcript, 0x8540), mload(add(transcript, 0x5f80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8500),
                        0x60,
                        add(transcript, 0x8500),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8560), mload(add(transcript, 0x8480)))
            mstore(add(transcript, 0x8580), mload(add(transcript, 0x84a0)))
            mstore(add(transcript, 0x85a0), mload(add(transcript, 0x8500)))
            mstore(add(transcript, 0x85c0), mload(add(transcript, 0x8520)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8560),
                        0x80,
                        add(transcript, 0x8560),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x85e0),
                0x1351fc9802bbb52a1226805a5530d2b2ab099d55dc3dad0ea61bf0a3d03ac65a
            )
            mstore(
                add(transcript, 0x8600),
                0x1e027f8cbd6fd74937d1a1c78912a2be0838b7fa55642b5dd343743d485ddd8e
            )
            mstore(add(transcript, 0x8620), mload(add(transcript, 0x5fa0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x85e0),
                        0x60,
                        add(transcript, 0x85e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8640), mload(add(transcript, 0x8560)))
            mstore(add(transcript, 0x8660), mload(add(transcript, 0x8580)))
            mstore(add(transcript, 0x8680), mload(add(transcript, 0x85e0)))
            mstore(add(transcript, 0x86a0), mload(add(transcript, 0x8600)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8640),
                        0x80,
                        add(transcript, 0x8640),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x86c0),
                0x03583b542cc7d040dce0709bedf0b142d6897d7d5ac1f9ad73ec7c099dfdec4a
            )
            mstore(
                add(transcript, 0x86e0),
                0x16c92034947c0dce23afff582a863f58b8baa4222dc7c0c0ad24f1505182d421
            )
            mstore(add(transcript, 0x8700), mload(add(transcript, 0x5fc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x86c0),
                        0x60,
                        add(transcript, 0x86c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8720), mload(add(transcript, 0x8640)))
            mstore(add(transcript, 0x8740), mload(add(transcript, 0x8660)))
            mstore(add(transcript, 0x8760), mload(add(transcript, 0x86c0)))
            mstore(add(transcript, 0x8780), mload(add(transcript, 0x86e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8720),
                        0x80,
                        add(transcript, 0x8720),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x87a0),
                0x01be65e3d8b075562dc246951d8945391e0905fac6100b53d07cc939f2e7b57e
            )
            mstore(
                add(transcript, 0x87c0),
                0x0de0ea7103578ce07eca5dd3e539e3f21d1d5c08e3f973f5c0d8492b43dda412
            )
            mstore(add(transcript, 0x87e0), mload(add(transcript, 0x5fe0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x87a0),
                        0x60,
                        add(transcript, 0x87a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8800), mload(add(transcript, 0x8720)))
            mstore(add(transcript, 0x8820), mload(add(transcript, 0x8740)))
            mstore(add(transcript, 0x8840), mload(add(transcript, 0x87a0)))
            mstore(add(transcript, 0x8860), mload(add(transcript, 0x87c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8800),
                        0x80,
                        add(transcript, 0x8800),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8880),
                0x2eaf4bbade1b090669b1859a5dcb6cca4666ef2758c8032e09bcdb0f914040c4
            )
            mstore(
                add(transcript, 0x88a0),
                0x2e002e049cb5ee04cd8e9cdf556590da1bf305ead03a5a94c404f0517d1dd2a2
            )
            mstore(add(transcript, 0x88c0), mload(add(transcript, 0x6000)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8880),
                        0x60,
                        add(transcript, 0x8880),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x88e0), mload(add(transcript, 0x8800)))
            mstore(add(transcript, 0x8900), mload(add(transcript, 0x8820)))
            mstore(add(transcript, 0x8920), mload(add(transcript, 0x8880)))
            mstore(add(transcript, 0x8940), mload(add(transcript, 0x88a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x88e0),
                        0x80,
                        add(transcript, 0x88e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8960),
                0x15ca52e0f2cee5aef3f540278207783e48480213afcb0e140e00401dfd29e2f6
            )
            mstore(
                add(transcript, 0x8980),
                0x16f50eded4eaac4f95dcfaef7326869aed43b2c9bf02a14fbfed1122599e928e
            )
            mstore(add(transcript, 0x89a0), mload(add(transcript, 0x6020)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8960),
                        0x60,
                        add(transcript, 0x8960),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x89c0), mload(add(transcript, 0x88e0)))
            mstore(add(transcript, 0x89e0), mload(add(transcript, 0x8900)))
            mstore(add(transcript, 0x8a00), mload(add(transcript, 0x8960)))
            mstore(add(transcript, 0x8a20), mload(add(transcript, 0x8980)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x89c0),
                        0x80,
                        add(transcript, 0x89c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8a40),
                0x2455b59180e98d1821bcc3fbdde24c8b44c30e68412ce76268db54f175c48e4e
            )
            mstore(
                add(transcript, 0x8a60),
                0x14fc0e5dabefb266d7fb3544681610c63b24270f5f6565fb8bc3089daf0546cd
            )
            mstore(add(transcript, 0x8a80), mload(add(transcript, 0x6040)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8a40),
                        0x60,
                        add(transcript, 0x8a40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8aa0), mload(add(transcript, 0x89c0)))
            mstore(add(transcript, 0x8ac0), mload(add(transcript, 0x89e0)))
            mstore(add(transcript, 0x8ae0), mload(add(transcript, 0x8a40)))
            mstore(add(transcript, 0x8b00), mload(add(transcript, 0x8a60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8aa0),
                        0x80,
                        add(transcript, 0x8aa0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8b20),
                0x2fb7565286ce91a88127f7e82556c394a0a32958a9dd130038394cef545b20fc
            )
            mstore(
                add(transcript, 0x8b40),
                0x2e5e7bf3aeaa3bd64baf42fd46e3d9bb80e8a95b6a26d6d71610f3e620bca627
            )
            mstore(add(transcript, 0x8b60), mload(add(transcript, 0x6060)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8b20),
                        0x60,
                        add(transcript, 0x8b20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8b80), mload(add(transcript, 0x8aa0)))
            mstore(add(transcript, 0x8ba0), mload(add(transcript, 0x8ac0)))
            mstore(add(transcript, 0x8bc0), mload(add(transcript, 0x8b20)))
            mstore(add(transcript, 0x8be0), mload(add(transcript, 0x8b40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8b80),
                        0x80,
                        add(transcript, 0x8b80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8c00),
                0x2a631f12728207fd2c6d094191c3bc365d59ab2febe86c0a2c4acd71998a1738
            )
            mstore(
                add(transcript, 0x8c20),
                0x2033b2b8ac885815b55af73506ecec2ebeaa7f0fe8b4108d30ce45efccc6b449
            )
            mstore(add(transcript, 0x8c40), mload(add(transcript, 0x6080)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8c00),
                        0x60,
                        add(transcript, 0x8c00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8c60), mload(add(transcript, 0x8b80)))
            mstore(add(transcript, 0x8c80), mload(add(transcript, 0x8ba0)))
            mstore(add(transcript, 0x8ca0), mload(add(transcript, 0x8c00)))
            mstore(add(transcript, 0x8cc0), mload(add(transcript, 0x8c20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8c60),
                        0x80,
                        add(transcript, 0x8c60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8ce0),
                0x20b03ccda6086e5e83f58dc6e728743cfcf3d298c475bf1c1bcc06773129dff4
            )
            mstore(
                add(transcript, 0x8d00),
                0x25c70f96e47302e42d0b43bff247eebf4f7d84d191683622009b98268f8b960c
            )
            mstore(add(transcript, 0x8d20), mload(add(transcript, 0x60a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8ce0),
                        0x60,
                        add(transcript, 0x8ce0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8d40), mload(add(transcript, 0x8c60)))
            mstore(add(transcript, 0x8d60), mload(add(transcript, 0x8c80)))
            mstore(add(transcript, 0x8d80), mload(add(transcript, 0x8ce0)))
            mstore(add(transcript, 0x8da0), mload(add(transcript, 0x8d00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8d40),
                        0x80,
                        add(transcript, 0x8d40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x8dc0),
                0x13d52dfe1f53916f91b2ba176be18d5fd7c1e6605528b4a555facadcce06cb2a
            )
            mstore(
                add(transcript, 0x8de0),
                0x1f3c397f4d3d3b7b948e05192e8cdb04f7f6ea39a80063f26b509138267a0ff2
            )
            mstore(add(transcript, 0x8e00), mload(add(transcript, 0x60c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8dc0),
                        0x60,
                        add(transcript, 0x8dc0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8e20), mload(add(transcript, 0x8d40)))
            mstore(add(transcript, 0x8e40), mload(add(transcript, 0x8d60)))
            mstore(add(transcript, 0x8e60), mload(add(transcript, 0x8dc0)))
            mstore(add(transcript, 0x8e80), mload(add(transcript, 0x8de0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8e20),
                        0x80,
                        add(transcript, 0x8e20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8ea0), mload(add(transcript, 0x980)))
            mstore(add(transcript, 0x8ec0), mload(add(transcript, 0x9a0)))
            mstore(add(transcript, 0x8ee0), mload(add(transcript, 0x60e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8ea0),
                        0x60,
                        add(transcript, 0x8ea0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8f00), mload(add(transcript, 0x8e20)))
            mstore(add(transcript, 0x8f20), mload(add(transcript, 0x8e40)))
            mstore(add(transcript, 0x8f40), mload(add(transcript, 0x8ea0)))
            mstore(add(transcript, 0x8f60), mload(add(transcript, 0x8ec0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8f00),
                        0x80,
                        add(transcript, 0x8f00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8f80), mload(add(transcript, 0x9c0)))
            mstore(add(transcript, 0x8fa0), mload(add(transcript, 0x9e0)))
            mstore(add(transcript, 0x8fc0), mload(add(transcript, 0x6100)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x8f80),
                        0x60,
                        add(transcript, 0x8f80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x8fe0), mload(add(transcript, 0x8f00)))
            mstore(add(transcript, 0x9000), mload(add(transcript, 0x8f20)))
            mstore(add(transcript, 0x9020), mload(add(transcript, 0x8f80)))
            mstore(add(transcript, 0x9040), mload(add(transcript, 0x8fa0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x8fe0),
                        0x80,
                        add(transcript, 0x8fe0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9060), mload(add(transcript, 0xa00)))
            mstore(add(transcript, 0x9080), mload(add(transcript, 0xa20)))
            mstore(add(transcript, 0x90a0), mload(add(transcript, 0x6120)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9060),
                        0x60,
                        add(transcript, 0x9060),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x90c0), mload(add(transcript, 0x8fe0)))
            mstore(add(transcript, 0x90e0), mload(add(transcript, 0x9000)))
            mstore(add(transcript, 0x9100), mload(add(transcript, 0x9060)))
            mstore(add(transcript, 0x9120), mload(add(transcript, 0x9080)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x90c0),
                        0x80,
                        add(transcript, 0x90c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9140), mload(add(transcript, 0xa40)))
            mstore(add(transcript, 0x9160), mload(add(transcript, 0xa60)))
            mstore(add(transcript, 0x9180), mload(add(transcript, 0x6140)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9140),
                        0x60,
                        add(transcript, 0x9140),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x91a0), mload(add(transcript, 0x90c0)))
            mstore(add(transcript, 0x91c0), mload(add(transcript, 0x90e0)))
            mstore(add(transcript, 0x91e0), mload(add(transcript, 0x9140)))
            mstore(add(transcript, 0x9200), mload(add(transcript, 0x9160)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x91a0),
                        0x80,
                        add(transcript, 0x91a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9220), mload(add(transcript, 0x8e0)))
            mstore(add(transcript, 0x9240), mload(add(transcript, 0x900)))
            mstore(add(transcript, 0x9260), mload(add(transcript, 0x6160)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9220),
                        0x60,
                        add(transcript, 0x9220),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9280), mload(add(transcript, 0x91a0)))
            mstore(add(transcript, 0x92a0), mload(add(transcript, 0x91c0)))
            mstore(add(transcript, 0x92c0), mload(add(transcript, 0x9220)))
            mstore(add(transcript, 0x92e0), mload(add(transcript, 0x9240)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9280),
                        0x80,
                        add(transcript, 0x9280),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9300), mload(add(transcript, 0x1260)))
            mstore(add(transcript, 0x9320), mload(add(transcript, 0x1280)))
            mstore(add(transcript, 0x9340), mload(add(transcript, 0x6900)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9300),
                        0x60,
                        add(transcript, 0x9300),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9360), mload(add(transcript, 0x9280)))
            mstore(add(transcript, 0x9380), mload(add(transcript, 0x92a0)))
            mstore(add(transcript, 0x93a0), mload(add(transcript, 0x9300)))
            mstore(add(transcript, 0x93c0), mload(add(transcript, 0x9320)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9360),
                        0x80,
                        add(transcript, 0x9360),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x93e0), mload(add(transcript, 0x12a0)))
            mstore(add(transcript, 0x9400), mload(add(transcript, 0x12c0)))
            mstore(add(transcript, 0x9420), mload(add(transcript, 0x6940)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x93e0),
                        0x60,
                        add(transcript, 0x93e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9440), mload(add(transcript, 0x9360)))
            mstore(add(transcript, 0x9460), mload(add(transcript, 0x9380)))
            mstore(add(transcript, 0x9480), mload(add(transcript, 0x93e0)))
            mstore(add(transcript, 0x94a0), mload(add(transcript, 0x9400)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9440),
                        0x80,
                        add(transcript, 0x9440),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x94c0), mload(add(transcript, 0x12e0)))
            mstore(add(transcript, 0x94e0), mload(add(transcript, 0x1300)))
            mstore(add(transcript, 0x9500), mload(add(transcript, 0x6980)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x94c0),
                        0x60,
                        add(transcript, 0x94c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9520), mload(add(transcript, 0x9440)))
            mstore(add(transcript, 0x9540), mload(add(transcript, 0x9460)))
            mstore(add(transcript, 0x9560), mload(add(transcript, 0x94c0)))
            mstore(add(transcript, 0x9580), mload(add(transcript, 0x94e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9520),
                        0x80,
                        add(transcript, 0x9520),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x95a0), mload(add(transcript, 0x1320)))
            mstore(add(transcript, 0x95c0), mload(add(transcript, 0x1340)))
            mstore(add(transcript, 0x95e0), mload(add(transcript, 0x69c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x95a0),
                        0x60,
                        add(transcript, 0x95a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9600), mload(add(transcript, 0x9520)))
            mstore(add(transcript, 0x9620), mload(add(transcript, 0x9540)))
            mstore(add(transcript, 0x9640), mload(add(transcript, 0x95a0)))
            mstore(add(transcript, 0x9660), mload(add(transcript, 0x95c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9600),
                        0x80,
                        add(transcript, 0x9600),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9680), mload(add(transcript, 0x12a0)))
            mstore(add(transcript, 0x96a0), mload(add(transcript, 0x12c0)))
            mstore(add(transcript, 0x96c0), mload(add(transcript, 0x6380)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9680),
                        0x60,
                        add(transcript, 0x9680),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x96e0), mload(add(transcript, 0x1260)))
            mstore(add(transcript, 0x9700), mload(add(transcript, 0x1280)))
            mstore(add(transcript, 0x9720), mload(add(transcript, 0x9680)))
            mstore(add(transcript, 0x9740), mload(add(transcript, 0x96a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x96e0),
                        0x80,
                        add(transcript, 0x96e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9760), mload(add(transcript, 0x12e0)))
            mstore(add(transcript, 0x9780), mload(add(transcript, 0x1300)))
            mstore(add(transcript, 0x97a0), mload(add(transcript, 0x65e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9760),
                        0x60,
                        add(transcript, 0x9760),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x97c0), mload(add(transcript, 0x96e0)))
            mstore(add(transcript, 0x97e0), mload(add(transcript, 0x9700)))
            mstore(add(transcript, 0x9800), mload(add(transcript, 0x9760)))
            mstore(add(transcript, 0x9820), mload(add(transcript, 0x9780)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x97c0),
                        0x80,
                        add(transcript, 0x97c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9840), mload(add(transcript, 0x1320)))
            mstore(add(transcript, 0x9860), mload(add(transcript, 0x1340)))
            mstore(add(transcript, 0x9880), mload(add(transcript, 0x6780)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9840),
                        0x60,
                        add(transcript, 0x9840),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x98a0), mload(add(transcript, 0x97c0)))
            mstore(add(transcript, 0x98c0), mload(add(transcript, 0x97e0)))
            mstore(add(transcript, 0x98e0), mload(add(transcript, 0x9840)))
            mstore(add(transcript, 0x9900), mload(add(transcript, 0x9860)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x98a0),
                        0x80,
                        add(transcript, 0x98a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9920), mload(add(transcript, 0x9600)))
            mstore(add(transcript, 0x9940), mload(add(transcript, 0x9620)))
            mstore(add(transcript, 0x9960), mload(add(transcript, 0x98a0)))
            mstore(add(transcript, 0x9980), mload(add(transcript, 0x98c0)))
            mstore(add(transcript, 0x99a0), mload(add(transcript, 0x13c0)))
            mstore(add(transcript, 0x99c0), mload(add(transcript, 0x13e0)))
            mstore(add(transcript, 0x99e0), mload(add(transcript, 0x1400)))
            mstore(add(transcript, 0x9a00), mload(add(transcript, 0x1420)))
            mstore(
                add(transcript, 0x9a20),
                keccak256(add(transcript, 0x9920), 256)
            )
            mstore(add(transcript, 0x9a40), mod(mload(39456), f_q))
            mstore(
                add(transcript, 0x9a60),
                mulmod(
                    mload(add(transcript, 0x9a40)),
                    mload(add(transcript, 0x9a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x9a80),
                mulmod(1, mload(add(transcript, 0x9a40)), f_q)
            )
            mstore(add(transcript, 0x9aa0), mload(add(transcript, 0x99a0)))
            mstore(add(transcript, 0x9ac0), mload(add(transcript, 0x99c0)))
            mstore(add(transcript, 0x9ae0), mload(add(transcript, 0x9a80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x9aa0),
                        0x60,
                        add(transcript, 0x9aa0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9b00), mload(add(transcript, 0x9920)))
            mstore(add(transcript, 0x9b20), mload(add(transcript, 0x9940)))
            mstore(add(transcript, 0x9b40), mload(add(transcript, 0x9aa0)))
            mstore(add(transcript, 0x9b60), mload(add(transcript, 0x9ac0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x9b00),
                        0x80,
                        add(transcript, 0x9b00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x9b80), mload(add(transcript, 0x99e0)))
            mstore(add(transcript, 0x9ba0), mload(add(transcript, 0x9a00)))
            mstore(add(transcript, 0x9bc0), mload(add(transcript, 0x9a80)))
            // success := and(
            //     eq(
            //         staticcall(
            //             gas(),
            //             0x7,
            //             add(transcript, 0x9b80),
            //             0x60,
            //             add(transcript, 0x9b80),
            //             0x40
            //         ),
            //         1
            //     ),
            //     success
            // )
            // mstore(add(transcript, 0x9be0), mload(add(transcript, 0x9960)))
            // mstore(add(transcript, 0x9c00), mload(add(transcript, 0x9980)))
            mstore(add(transcript, 0x9c20), mload(add(transcript, 0x9b80)))
            mstore(add(transcript, 0x9c40), mload(add(transcript, 0x9ba0)))
            // success := and(
            //     eq(
            //         staticcall(
            //             gas(),
            //             0x6,
            //             add(transcript, 0x9be0),
            //             0x80,
            //             add(transcript, 0x9be0),
            //             0x40
            //         ),
            //         1
            //     ),
            //     success
            // )
            // mstore(add(transcript, 0x9c60), mload(add(transcript, 0x9b00)))
            // mstore(add(transcript, 0x9c80), mload(add(transcript, 0x9b20)))
            mstore(
                add(transcript, 0x9ca0),
                0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
            )
            mstore(
                add(transcript, 0x9cc0),
                0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
            )
            mstore(
                add(transcript, 0x9ce0),
                0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
            )
            mstore(
                add(transcript, 0x9d00),
                0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
            )
            mstore(add(transcript, 0x9d20), mload(add(transcript, 0x9be0)))
            mstore(add(transcript, 0x9d40), mload(add(transcript, 0x9c00)))
            mstore(
                add(transcript, 0x9d60),
                0x1784828dba0bca3bf388d7c1754450f55517727147ef209aed9a9b8f2f41d032
            )
            mstore(
                add(transcript, 0x9d80),
                0x23dc34be95c31df1b7928f46c55833ad31a1430f5d87316f115cd2f46cf6922f
            )
            mstore(
                add(transcript, 0x9da0),
                0x1dcf87c3133c329d8e76613e93e3c694c581d7859ce59b613eb9d5bcb726b884
            )
            mstore(
                add(transcript, 0x9dc0),
                0x03aaeb883aaf2d06a46670a652e15177db87aa71218a980b93193c443c6c51fd
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x8,
                        add(transcript, 0x9c60),
                        0x180,
                        add(transcript, 0x9c60),
                        0x20
                    ),
                    1
                ),
                success
            )
            success := and(eq(mload(add(transcript, 0x9c60)), 1), success)
        }
        return success;
    }
}
