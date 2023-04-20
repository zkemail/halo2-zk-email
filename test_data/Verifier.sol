// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract Verifier {
    function verify(
        uint256[] memory pubInputs,
        bytes memory proof
    ) public view returns (bool) {
        bool success = true;
        bytes32[834] memory transcript;
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
                    let y_square_eq_x_cube_plus_3 := eq(x_cube_plus_3, y_square)
                    valid := and(y_square_eq_x_cube_plus_3, valid)
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
                add(transcript, 0x0),
                6239576148428485684541164309811669271287184001377876996293223870478722761346
            )
            {
                let x := mload(add(proof, 0x20))
                mstore(add(transcript, 0x1e0), x)
                let y := mload(add(proof, 0x40))
                mstore(add(transcript, 0x200), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x60))
                mstore(add(transcript, 0x220), x)
                let y := mload(add(proof, 0x80))
                mstore(add(transcript, 0x240), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0xa0))
                mstore(add(transcript, 0x260), x)
                let y := mload(add(proof, 0xc0))
                mstore(add(transcript, 0x280), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0xe0))
                mstore(add(transcript, 0x2a0), x)
                let y := mload(add(proof, 0x100))
                mstore(add(transcript, 0x2c0), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(add(transcript, 0x2e0), keccak256(add(transcript, 0x0), 736))
            {
                let hash := mload(add(transcript, 0x2e0))
                mstore(add(transcript, 0x300), mod(hash, f_q))
                mstore(add(transcript, 0x320), hash)
            }
            {
                let x := mload(add(proof, 0x120))
                mstore(add(transcript, 0x340), x)
                let y := mload(add(proof, 0x140))
                mstore(add(transcript, 0x360), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x160))
                mstore(add(transcript, 0x380), x)
                let y := mload(add(proof, 0x180))
                mstore(add(transcript, 0x3a0), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x3c0),
                keccak256(add(transcript, 0x320), 160)
            )
            {
                let hash := mload(add(transcript, 0x3c0))
                mstore(add(transcript, 0x3e0), mod(hash, f_q))
                mstore(add(transcript, 0x400), hash)
            }
            mstore8(add(transcript, 0x420), 1)
            mstore(
                add(transcript, 0x420),
                keccak256(add(transcript, 0x400), 33)
            )
            {
                let hash := mload(add(transcript, 0x420))
                mstore(add(transcript, 0x440), mod(hash, f_q))
                mstore(add(transcript, 0x460), hash)
            }
            {
                let x := mload(add(proof, 0x1a0))
                mstore(add(transcript, 0x480), x)
                let y := mload(add(proof, 0x1c0))
                mstore(add(transcript, 0x4a0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x1e0))
                mstore(add(transcript, 0x4c0), x)
                let y := mload(add(proof, 0x200))
                mstore(add(transcript, 0x4e0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x220))
                mstore(add(transcript, 0x500), x)
                let y := mload(add(proof, 0x240))
                mstore(add(transcript, 0x520), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x260))
                mstore(add(transcript, 0x540), x)
                let y := mload(add(proof, 0x280))
                mstore(add(transcript, 0x560), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x2a0))
                mstore(add(transcript, 0x580), x)
                let y := mload(add(proof, 0x2c0))
                mstore(add(transcript, 0x5a0), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x5c0),
                keccak256(add(transcript, 0x460), 352)
            )
            {
                let hash := mload(add(transcript, 0x5c0))
                mstore(add(transcript, 0x5e0), mod(hash, f_q))
                mstore(add(transcript, 0x600), hash)
            }
            {
                let x := mload(add(proof, 0x2e0))
                mstore(add(transcript, 0x620), x)
                let y := mload(add(proof, 0x300))
                mstore(add(transcript, 0x640), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x320))
                mstore(add(transcript, 0x660), x)
                let y := mload(add(proof, 0x340))
                mstore(add(transcript, 0x680), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x360))
                mstore(add(transcript, 0x6a0), x)
                let y := mload(add(proof, 0x380))
                mstore(add(transcript, 0x6c0), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x6e0),
                keccak256(add(transcript, 0x600), 224)
            )
            {
                let hash := mload(add(transcript, 0x6e0))
                mstore(add(transcript, 0x700), mod(hash, f_q))
                mstore(add(transcript, 0x720), hash)
            }
            mstore(add(transcript, 0x740), mod(mload(add(proof, 0x3a0)), f_q))
            mstore(add(transcript, 0x760), mod(mload(add(proof, 0x3c0)), f_q))
            mstore(add(transcript, 0x780), mod(mload(add(proof, 0x3e0)), f_q))
            mstore(add(transcript, 0x7a0), mod(mload(add(proof, 0x400)), f_q))
            mstore(add(transcript, 0x7c0), mod(mload(add(proof, 0x420)), f_q))
            mstore(add(transcript, 0x7e0), mod(mload(add(proof, 0x440)), f_q))
            mstore(add(transcript, 0x800), mod(mload(add(proof, 0x460)), f_q))
            mstore(add(transcript, 0x820), mod(mload(add(proof, 0x480)), f_q))
            mstore(add(transcript, 0x840), mod(mload(add(proof, 0x4a0)), f_q))
            mstore(add(transcript, 0x860), mod(mload(add(proof, 0x4c0)), f_q))
            mstore(add(transcript, 0x880), mod(mload(add(proof, 0x4e0)), f_q))
            mstore(add(transcript, 0x8a0), mod(mload(add(proof, 0x500)), f_q))
            mstore(add(transcript, 0x8c0), mod(mload(add(proof, 0x520)), f_q))
            mstore(add(transcript, 0x8e0), mod(mload(add(proof, 0x540)), f_q))
            mstore(add(transcript, 0x900), mod(mload(add(proof, 0x560)), f_q))
            mstore(add(transcript, 0x920), mod(mload(add(proof, 0x580)), f_q))
            mstore(add(transcript, 0x940), mod(mload(add(proof, 0x5a0)), f_q))
            mstore(add(transcript, 0x960), mod(mload(add(proof, 0x5c0)), f_q))
            mstore(add(transcript, 0x980), mod(mload(add(proof, 0x5e0)), f_q))
            mstore(add(transcript, 0x9a0), mod(mload(add(proof, 0x600)), f_q))
            mstore(add(transcript, 0x9c0), mod(mload(add(proof, 0x620)), f_q))
            mstore(add(transcript, 0x9e0), mod(mload(add(proof, 0x640)), f_q))
            mstore(add(transcript, 0xa00), mod(mload(add(proof, 0x660)), f_q))
            mstore(add(transcript, 0xa20), mod(mload(add(proof, 0x680)), f_q))
            mstore(add(transcript, 0xa40), mod(mload(add(proof, 0x6a0)), f_q))
            mstore(add(transcript, 0xa60), mod(mload(add(proof, 0x6c0)), f_q))
            mstore(add(transcript, 0xa80), mod(mload(add(proof, 0x6e0)), f_q))
            mstore(add(transcript, 0xaa0), mod(mload(add(proof, 0x700)), f_q))
            mstore(add(transcript, 0xac0), mod(mload(add(proof, 0x720)), f_q))
            mstore(add(transcript, 0xae0), mod(mload(add(proof, 0x740)), f_q))
            mstore(add(transcript, 0xb00), mod(mload(add(proof, 0x760)), f_q))
            mstore(add(transcript, 0xb20), mod(mload(add(proof, 0x780)), f_q))
            mstore(add(transcript, 0xb40), mod(mload(add(proof, 0x7a0)), f_q))
            mstore(add(transcript, 0xb60), mod(mload(add(proof, 0x7c0)), f_q))
            mstore(add(transcript, 0xb80), mod(mload(add(proof, 0x7e0)), f_q))
            mstore(add(transcript, 0xba0), mod(mload(add(proof, 0x800)), f_q))
            mstore(add(transcript, 0xbc0), mod(mload(add(proof, 0x820)), f_q))
            mstore(
                add(transcript, 0xbe0),
                keccak256(add(transcript, 0x720), 1216)
            )
            {
                let hash := mload(add(transcript, 0xbe0))
                mstore(add(transcript, 0xc00), mod(hash, f_q))
                mstore(add(transcript, 0xc20), hash)
            }
            mstore8(add(transcript, 0xc40), 1)
            mstore(
                add(transcript, 0xc40),
                keccak256(add(transcript, 0xc20), 33)
            )
            {
                let hash := mload(add(transcript, 0xc40))
                mstore(add(transcript, 0xc60), mod(hash, f_q))
                mstore(add(transcript, 0xc80), hash)
            }
            {
                let x := mload(add(proof, 0x840))
                mstore(add(transcript, 0xca0), x)
                let y := mload(add(proof, 0x860))
                mstore(add(transcript, 0xcc0), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0xce0),
                keccak256(add(transcript, 0xc80), 96)
            )
            {
                let hash := mload(add(transcript, 0xce0))
                mstore(add(transcript, 0xd00), mod(hash, f_q))
                mstore(add(transcript, 0xd20), hash)
            }
            {
                let x := mload(add(proof, 0x880))
                mstore(add(transcript, 0xd40), x)
                let y := mload(add(proof, 0x8a0))
                mstore(add(transcript, 0xd60), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(transcript, 0x20))
                x := add(x, shl(88, mload(add(transcript, 0x40))))
                x := add(x, shl(176, mload(add(transcript, 0x60))))
                mstore(add(transcript, 0xd80), x)
                let y := mload(add(transcript, 0x80))
                y := add(y, shl(88, mload(add(transcript, 0xa0))))
                y := add(y, shl(176, mload(add(transcript, 0xc0))))
                mstore(add(transcript, 0xda0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(transcript, 0xe0))
                x := add(x, shl(88, mload(add(transcript, 0x100))))
                x := add(x, shl(176, mload(add(transcript, 0x120))))
                mstore(add(transcript, 0xdc0), x)
                let y := mload(add(transcript, 0x140))
                y := add(y, shl(88, mload(add(transcript, 0x160))))
                y := add(y, shl(176, mload(add(transcript, 0x180))))
                mstore(add(transcript, 0xde0), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0xe00),
                mulmod(
                    mload(add(transcript, 0x700)),
                    mload(add(transcript, 0x700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe20),
                mulmod(
                    mload(add(transcript, 0xe00)),
                    mload(add(transcript, 0xe00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe40),
                mulmod(
                    mload(add(transcript, 0xe20)),
                    mload(add(transcript, 0xe20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe60),
                mulmod(
                    mload(add(transcript, 0xe40)),
                    mload(add(transcript, 0xe40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe80),
                mulmod(
                    mload(add(transcript, 0xe60)),
                    mload(add(transcript, 0xe60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xea0),
                mulmod(
                    mload(add(transcript, 0xe80)),
                    mload(add(transcript, 0xe80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xec0),
                mulmod(
                    mload(add(transcript, 0xea0)),
                    mload(add(transcript, 0xea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xee0),
                mulmod(
                    mload(add(transcript, 0xec0)),
                    mload(add(transcript, 0xec0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf00),
                mulmod(
                    mload(add(transcript, 0xee0)),
                    mload(add(transcript, 0xee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf20),
                mulmod(
                    mload(add(transcript, 0xf00)),
                    mload(add(transcript, 0xf00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf40),
                mulmod(
                    mload(add(transcript, 0xf20)),
                    mload(add(transcript, 0xf20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf60),
                mulmod(
                    mload(add(transcript, 0xf40)),
                    mload(add(transcript, 0xf40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf80),
                mulmod(
                    mload(add(transcript, 0xf60)),
                    mload(add(transcript, 0xf60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfa0),
                mulmod(
                    mload(add(transcript, 0xf80)),
                    mload(add(transcript, 0xf80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfc0),
                mulmod(
                    mload(add(transcript, 0xfa0)),
                    mload(add(transcript, 0xfa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfe0),
                mulmod(
                    mload(add(transcript, 0xfc0)),
                    mload(add(transcript, 0xfc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1000),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    mload(add(transcript, 0xfe0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1020),
                mulmod(
                    mload(add(transcript, 0x1000)),
                    mload(add(transcript, 0x1000)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1040),
                mulmod(
                    mload(add(transcript, 0x1020)),
                    mload(add(transcript, 0x1020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1060),
                mulmod(
                    mload(add(transcript, 0x1040)),
                    mload(add(transcript, 0x1040)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1080),
                mulmod(
                    mload(add(transcript, 0x1060)),
                    mload(add(transcript, 0x1060)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x10a0),
                mulmod(
                    mload(add(transcript, 0x1080)),
                    mload(add(transcript, 0x1080)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x10c0),
                mulmod(
                    mload(add(transcript, 0x10a0)),
                    mload(add(transcript, 0x10a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x10e0),
                mulmod(
                    mload(add(transcript, 0x10c0)),
                    mload(add(transcript, 0x10c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1100),
                addmod(
                    mload(add(transcript, 0x10e0)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1120),
                mulmod(
                    mload(add(transcript, 0x1100)),
                    21888241567198334088790460357988866238279339518792980768180410072331574733841,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1140),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    12929131318670223636853686797196826072950305380535537217467769528748593133487,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1160),
                addmod(
                    mload(add(transcript, 0x700)),
                    8959111553169051585392718948060449015598059019880497126230434657827215362130,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1180),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    14655294445420895451632927078981340937842238432098198055057679026789553137428,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x11a0),
                addmod(
                    mload(add(transcript, 0x700)),
                    7232948426418379770613478666275934150706125968317836288640525159786255358189,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x11c0),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    12220484078924208264862893648548198807365556694478604924193442790112568454894,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x11e0),
                addmod(
                    mload(add(transcript, 0x700)),
                    9667758792915066957383512096709076281182807705937429419504761396463240040723,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1200),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    8734126352828345679573237859165904705806588461301144420590422589042130041188,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1220),
                addmod(
                    mload(add(transcript, 0x700)),
                    13154116519010929542673167886091370382741775939114889923107781597533678454429,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1240),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    7358966525675286471217089135633860168646304224547606326237275077574224349359,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1260),
                addmod(
                    mload(add(transcript, 0x700)),
                    14529276346163988751029316609623414919902060175868428017460929109001584146258,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1280),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    9741553891420464328295280489650144566903017206473301385034033384879943874347,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x12a0),
                addmod(
                    mload(add(transcript, 0x700)),
                    12146688980418810893951125255607130521645347193942732958664170801695864621270,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x12c0),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    17329448237240114492580865744088056414251735686965494637158808787419781175510,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x12e0),
                addmod(
                    mload(add(transcript, 0x700)),
                    4558794634599160729665540001169218674296628713450539706539395399156027320107,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1300),
                mulmod(mload(add(transcript, 0x1120)), 1, f_q)
            )
            mstore(
                add(transcript, 0x1320),
                addmod(
                    mload(add(transcript, 0x700)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1340),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    11451405578697956743456240853980216273390554734748796433026540431386972584651,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1360),
                addmod(
                    mload(add(transcript, 0x700)),
                    10436837293141318478790164891277058815157809665667237910671663755188835910966,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1380),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    8374374965308410102411073611984011876711565317741801500439755773472076597347,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x13a0),
                addmod(
                    mload(add(transcript, 0x700)),
                    13513867906530865119835332133273263211836799082674232843258448413103731898270,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x13c0),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    21490807004895109926141140246143262403290679459142140821740925192625185504522,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x13e0),
                addmod(
                    mload(add(transcript, 0x700)),
                    397435866944165296105265499114012685257684941273893521957278993950622991095,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1400),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    11211301017135681023579411905410872569206244553457844956874280139879520583390,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1420),
                addmod(
                    mload(add(transcript, 0x700)),
                    10676941854703594198666993839846402519342119846958189386823924046696287912227,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1440),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    18846108080730935585192484934247867403156699586319724728525857970312957475341,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1460),
                addmod(
                    mload(add(transcript, 0x700)),
                    3042134791108339637053920811009407685391664814096309615172346216262851020276,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1480),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    3615478808282855240548287271348143516886772452944084747768312988864436725401,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14a0),
                addmod(
                    mload(add(transcript, 0x700)),
                    18272764063556419981698118473909131571661591947471949595929891197711371770216,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14c0),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    21451937155080765789602997556105366785934335730087568134349216848800867145453,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14e0),
                addmod(
                    mload(add(transcript, 0x700)),
                    436305716758509432643408189151908302614028670328466209348987337774941350164,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1500),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    1426404432721484388505361748317961535523355871255605456897797744433766488507,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1520),
                addmod(
                    mload(add(transcript, 0x700)),
                    20461838439117790833741043996939313553025008529160428886800406442142042007110,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1540),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    13982290267294411190096162596630216412723378687553046594730793425118513274800,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1560),
                addmod(
                    mload(add(transcript, 0x700)),
                    7905952604544864032150243148627058675824985712862987748967410761457295220817,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1580),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    216092043779272773661818549620449970334216366264741118684015851799902419467,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15a0),
                addmod(
                    mload(add(transcript, 0x700)),
                    21672150828060002448584587195636825118214148034151293225014188334775906076150,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15c0),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    9537783784440837896026284659246718978615447564543116209283382057778110278482,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15e0),
                addmod(
                    mload(add(transcript, 0x700)),
                    12350459087398437326220121086010556109932916835872918134414822128797698217135,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1600),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    12619617507853212586156872920672483948819476989779550311307282715684870266992,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1620),
                addmod(
                    mload(add(transcript, 0x700)),
                    9268625363986062636089532824584791139728887410636484032390921470890938228625,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1640),
                mulmod(
                    mload(add(transcript, 0x1120)),
                    3947443723575973965644279767310964219908423994086470065513888332899718123222,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1660),
                addmod(
                    mload(add(transcript, 0x700)),
                    17940799148263301256602125977946310868639940406329564278184315853676090372395,
                    f_q
                )
            )
            {
                let prod := mload(add(transcript, 0x1160))
                prod := mulmod(mload(add(transcript, 0x11a0)), prod, f_q)
                mstore(add(transcript, 0x1680), prod)
                prod := mulmod(mload(add(transcript, 0x11e0)), prod, f_q)
                mstore(add(transcript, 0x16a0), prod)
                prod := mulmod(mload(add(transcript, 0x1220)), prod, f_q)
                mstore(add(transcript, 0x16c0), prod)
                prod := mulmod(mload(add(transcript, 0x1260)), prod, f_q)
                mstore(add(transcript, 0x16e0), prod)
                prod := mulmod(mload(add(transcript, 0x12a0)), prod, f_q)
                mstore(add(transcript, 0x1700), prod)
                prod := mulmod(mload(add(transcript, 0x12e0)), prod, f_q)
                mstore(add(transcript, 0x1720), prod)
                prod := mulmod(mload(add(transcript, 0x1320)), prod, f_q)
                mstore(add(transcript, 0x1740), prod)
                prod := mulmod(mload(add(transcript, 0x1360)), prod, f_q)
                mstore(add(transcript, 0x1760), prod)
                prod := mulmod(mload(add(transcript, 0x13a0)), prod, f_q)
                mstore(add(transcript, 0x1780), prod)
                prod := mulmod(mload(add(transcript, 0x13e0)), prod, f_q)
                mstore(add(transcript, 0x17a0), prod)
                prod := mulmod(mload(add(transcript, 0x1420)), prod, f_q)
                mstore(add(transcript, 0x17c0), prod)
                prod := mulmod(mload(add(transcript, 0x1460)), prod, f_q)
                mstore(add(transcript, 0x17e0), prod)
                prod := mulmod(mload(add(transcript, 0x14a0)), prod, f_q)
                mstore(add(transcript, 0x1800), prod)
                prod := mulmod(mload(add(transcript, 0x14e0)), prod, f_q)
                mstore(add(transcript, 0x1820), prod)
                prod := mulmod(mload(add(transcript, 0x1520)), prod, f_q)
                mstore(add(transcript, 0x1840), prod)
                prod := mulmod(mload(add(transcript, 0x1560)), prod, f_q)
                mstore(add(transcript, 0x1860), prod)
                prod := mulmod(mload(add(transcript, 0x15a0)), prod, f_q)
                mstore(add(transcript, 0x1880), prod)
                prod := mulmod(mload(add(transcript, 0x15e0)), prod, f_q)
                mstore(add(transcript, 0x18a0), prod)
                prod := mulmod(mload(add(transcript, 0x1620)), prod, f_q)
                mstore(add(transcript, 0x18c0), prod)
                prod := mulmod(mload(add(transcript, 0x1660)), prod, f_q)
                mstore(add(transcript, 0x18e0), prod)
                prod := mulmod(mload(add(transcript, 0x1100)), prod, f_q)
                mstore(add(transcript, 0x1900), prod)
            }
            mstore(add(transcript, 0x1940), 32)
            mstore(add(transcript, 0x1960), 32)
            mstore(add(transcript, 0x1980), 32)
            mstore(add(transcript, 0x19a0), mload(add(transcript, 0x1900)))
            mstore(
                add(transcript, 0x19c0),
                21888242871839275222246405745257275088548364400416034343698204186575808495615
            )
            mstore(
                add(transcript, 0x19e0),
                21888242871839275222246405745257275088548364400416034343698204186575808495617
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x5,
                        add(transcript, 0x1940),
                        0xc0,
                        add(transcript, 0x1920),
                        0x20
                    ),
                    1
                ),
                success
            )
            {
                let inv := mload(add(transcript, 0x1920))
                let v
                v := mload(add(transcript, 0x1100))
                mstore(
                    add(transcript, 0x1100),
                    mulmod(mload(add(transcript, 0x18e0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1660))
                mstore(
                    add(transcript, 0x1660),
                    mulmod(mload(add(transcript, 0x18c0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1620))
                mstore(
                    add(transcript, 0x1620),
                    mulmod(mload(add(transcript, 0x18a0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x15e0))
                mstore(
                    add(transcript, 0x15e0),
                    mulmod(mload(add(transcript, 0x1880)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x15a0))
                mstore(
                    add(transcript, 0x15a0),
                    mulmod(mload(add(transcript, 0x1860)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1560))
                mstore(
                    add(transcript, 0x1560),
                    mulmod(mload(add(transcript, 0x1840)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1520))
                mstore(
                    add(transcript, 0x1520),
                    mulmod(mload(add(transcript, 0x1820)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x14e0))
                mstore(
                    add(transcript, 0x14e0),
                    mulmod(mload(add(transcript, 0x1800)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x14a0))
                mstore(
                    add(transcript, 0x14a0),
                    mulmod(mload(add(transcript, 0x17e0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1460))
                mstore(
                    add(transcript, 0x1460),
                    mulmod(mload(add(transcript, 0x17c0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1420))
                mstore(
                    add(transcript, 0x1420),
                    mulmod(mload(add(transcript, 0x17a0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x13e0))
                mstore(
                    add(transcript, 0x13e0),
                    mulmod(mload(add(transcript, 0x1780)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x13a0))
                mstore(
                    add(transcript, 0x13a0),
                    mulmod(mload(add(transcript, 0x1760)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1360))
                mstore(
                    add(transcript, 0x1360),
                    mulmod(mload(add(transcript, 0x1740)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1320))
                mstore(
                    add(transcript, 0x1320),
                    mulmod(mload(add(transcript, 0x1720)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x12e0))
                mstore(
                    add(transcript, 0x12e0),
                    mulmod(mload(add(transcript, 0x1700)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x12a0))
                mstore(
                    add(transcript, 0x12a0),
                    mulmod(mload(add(transcript, 0x16e0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1260))
                mstore(
                    add(transcript, 0x1260),
                    mulmod(mload(add(transcript, 0x16c0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1220))
                mstore(
                    add(transcript, 0x1220),
                    mulmod(mload(add(transcript, 0x16a0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x11e0))
                mstore(
                    add(transcript, 0x11e0),
                    mulmod(mload(add(transcript, 0x1680)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x11a0))
                mstore(
                    add(transcript, 0x11a0),
                    mulmod(mload(add(transcript, 0x1160)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                mstore(add(transcript, 0x1160), inv)
            }
            mstore(
                add(transcript, 0x1a00),
                mulmod(
                    mload(add(transcript, 0x1140)),
                    mload(add(transcript, 0x1160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a20),
                mulmod(
                    mload(add(transcript, 0x1180)),
                    mload(add(transcript, 0x11a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a40),
                mulmod(
                    mload(add(transcript, 0x11c0)),
                    mload(add(transcript, 0x11e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a60),
                mulmod(
                    mload(add(transcript, 0x1200)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a80),
                mulmod(
                    mload(add(transcript, 0x1240)),
                    mload(add(transcript, 0x1260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1aa0),
                mulmod(
                    mload(add(transcript, 0x1280)),
                    mload(add(transcript, 0x12a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ac0),
                mulmod(
                    mload(add(transcript, 0x12c0)),
                    mload(add(transcript, 0x12e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ae0),
                mulmod(
                    mload(add(transcript, 0x1300)),
                    mload(add(transcript, 0x1320)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b00),
                mulmod(
                    mload(add(transcript, 0x1340)),
                    mload(add(transcript, 0x1360)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b20),
                mulmod(
                    mload(add(transcript, 0x1380)),
                    mload(add(transcript, 0x13a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b40),
                mulmod(
                    mload(add(transcript, 0x13c0)),
                    mload(add(transcript, 0x13e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b60),
                mulmod(
                    mload(add(transcript, 0x1400)),
                    mload(add(transcript, 0x1420)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b80),
                mulmod(
                    mload(add(transcript, 0x1440)),
                    mload(add(transcript, 0x1460)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ba0),
                mulmod(
                    mload(add(transcript, 0x1480)),
                    mload(add(transcript, 0x14a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1bc0),
                mulmod(
                    mload(add(transcript, 0x14c0)),
                    mload(add(transcript, 0x14e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1be0),
                mulmod(
                    mload(add(transcript, 0x1500)),
                    mload(add(transcript, 0x1520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c00),
                mulmod(
                    mload(add(transcript, 0x1540)),
                    mload(add(transcript, 0x1560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c20),
                mulmod(
                    mload(add(transcript, 0x1580)),
                    mload(add(transcript, 0x15a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c40),
                mulmod(
                    mload(add(transcript, 0x15c0)),
                    mload(add(transcript, 0x15e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c60),
                mulmod(
                    mload(add(transcript, 0x1600)),
                    mload(add(transcript, 0x1620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c80),
                mulmod(
                    mload(add(transcript, 0x1640)),
                    mload(add(transcript, 0x1660)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x1ae0)),
                    mload(add(transcript, 0x20)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1b00)),
                        mload(add(transcript, 0x40)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1b20)),
                        mload(add(transcript, 0x60)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1b40)),
                        mload(add(transcript, 0x80)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1b60)),
                        mload(add(transcript, 0xa0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1b80)),
                        mload(add(transcript, 0xc0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1ba0)),
                        mload(add(transcript, 0xe0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1bc0)),
                        mload(add(transcript, 0x100)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1be0)),
                        mload(add(transcript, 0x120)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1c00)),
                        mload(add(transcript, 0x140)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1c20)),
                        mload(add(transcript, 0x160)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1c40)),
                        mload(add(transcript, 0x180)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1c60)),
                        mload(add(transcript, 0x1a0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1c80)),
                        mload(add(transcript, 0x1c0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x1ca0), result)
            }
            mstore(
                add(transcript, 0x1cc0),
                addmod(2, sub(f_q, mload(add(transcript, 0x920))), f_q)
            )
            mstore(
                add(transcript, 0x1ce0),
                mulmod(
                    mload(add(transcript, 0x1cc0)),
                    mload(add(transcript, 0x920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d00),
                mulmod(
                    mload(add(transcript, 0x780)),
                    mload(add(transcript, 0x760)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d20),
                addmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x1d00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d40),
                addmod(
                    mload(add(transcript, 0x1d20)),
                    sub(f_q, mload(add(transcript, 0x7a0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d60),
                mulmod(
                    mload(add(transcript, 0x1d40)),
                    mload(add(transcript, 0x1ce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d80),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x1d60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1da0),
                mulmod(
                    mload(add(transcript, 0x800)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1dc0),
                addmod(
                    mload(add(transcript, 0x7c0)),
                    mload(add(transcript, 0x1da0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1de0),
                addmod(
                    mload(add(transcript, 0x1dc0)),
                    sub(f_q, mload(add(transcript, 0x820))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e00),
                mulmod(
                    mload(add(transcript, 0x1de0)),
                    mload(add(transcript, 0x940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e20),
                addmod(
                    mload(add(transcript, 0x1d80)),
                    mload(add(transcript, 0x1e00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e40),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x1e20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e60),
                addmod(1, sub(f_q, mload(add(transcript, 0x920))), f_q)
            )
            mstore(
                add(transcript, 0x1e80),
                mulmod(
                    mload(add(transcript, 0x1e60)),
                    mload(add(transcript, 0x920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ea0),
                mulmod(
                    mload(add(transcript, 0x880)),
                    mload(add(transcript, 0x860)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ec0),
                addmod(
                    mload(add(transcript, 0x840)),
                    mload(add(transcript, 0x1ea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ee0),
                addmod(
                    mload(add(transcript, 0x1ec0)),
                    sub(f_q, mload(add(transcript, 0x8a0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1f00),
                mulmod(
                    mload(add(transcript, 0x1ee0)),
                    mload(add(transcript, 0x1e80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1f20),
                addmod(
                    mload(add(transcript, 0x1e40)),
                    mload(add(transcript, 0x1f00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1f40),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x1f20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1f60),
                addmod(1, sub(f_q, mload(add(transcript, 0xa40))), f_q)
            )
            mstore(
                add(transcript, 0x1f80),
                mulmod(
                    mload(add(transcript, 0x1f60)),
                    mload(add(transcript, 0x1ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1fa0),
                addmod(
                    mload(add(transcript, 0x1f40)),
                    mload(add(transcript, 0x1f80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1fc0),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x1fa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1fe0),
                mulmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0xb00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2000),
                addmod(
                    mload(add(transcript, 0x1fe0)),
                    sub(f_q, mload(add(transcript, 0xb00))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2020),
                mulmod(
                    mload(add(transcript, 0x2000)),
                    mload(add(transcript, 0x1a00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2040),
                addmod(
                    mload(add(transcript, 0x1fc0)),
                    mload(add(transcript, 0x2020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2060),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x2040)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2080),
                addmod(
                    mload(add(transcript, 0xaa0)),
                    sub(f_q, mload(add(transcript, 0xa80))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x20a0),
                mulmod(
                    mload(add(transcript, 0x2080)),
                    mload(add(transcript, 0x1ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x20c0),
                addmod(
                    mload(add(transcript, 0x2060)),
                    mload(add(transcript, 0x20a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x20e0),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x20c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2100),
                addmod(
                    mload(add(transcript, 0xb00)),
                    sub(f_q, mload(add(transcript, 0xae0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2120),
                mulmod(
                    mload(add(transcript, 0x2100)),
                    mload(add(transcript, 0x1ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2140),
                addmod(
                    mload(add(transcript, 0x20e0)),
                    mload(add(transcript, 0x2120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2160),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x2140)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2180),
                addmod(1, sub(f_q, mload(add(transcript, 0x1a00))), f_q)
            )
            mstore(
                add(transcript, 0x21a0),
                addmod(
                    mload(add(transcript, 0x1a20)),
                    mload(add(transcript, 0x1a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21c0),
                addmod(
                    mload(add(transcript, 0x21a0)),
                    mload(add(transcript, 0x1a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21e0),
                addmod(
                    mload(add(transcript, 0x21c0)),
                    mload(add(transcript, 0x1a80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2200),
                addmod(
                    mload(add(transcript, 0x21e0)),
                    mload(add(transcript, 0x1aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2220),
                addmod(
                    mload(add(transcript, 0x2200)),
                    mload(add(transcript, 0x1ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2240),
                addmod(
                    mload(add(transcript, 0x2180)),
                    sub(f_q, mload(add(transcript, 0x2220))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2260),
                mulmod(
                    mload(add(transcript, 0x980)),
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2280),
                addmod(
                    mload(add(transcript, 0x8e0)),
                    mload(add(transcript, 0x2260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22a0),
                addmod(
                    mload(add(transcript, 0x2280)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22c0),
                mulmod(
                    mload(add(transcript, 0x9a0)),
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22e0),
                addmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x22c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2300),
                addmod(
                    mload(add(transcript, 0x22e0)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2320),
                mulmod(
                    mload(add(transcript, 0x2300)),
                    mload(add(transcript, 0x22a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2340),
                mulmod(
                    mload(add(transcript, 0x2320)),
                    mload(add(transcript, 0xa60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2360),
                mulmod(1, mload(add(transcript, 0x3e0)), f_q)
            )
            mstore(
                add(transcript, 0x2380),
                mulmod(
                    mload(add(transcript, 0x700)),
                    mload(add(transcript, 0x2360)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23a0),
                addmod(
                    mload(add(transcript, 0x8e0)),
                    mload(add(transcript, 0x2380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23c0),
                addmod(
                    mload(add(transcript, 0x23a0)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23e0),
                mulmod(
                    4131629893567559867359510883348571134090853742863529169391034518566172092834,
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2400),
                mulmod(
                    mload(add(transcript, 0x700)),
                    mload(add(transcript, 0x23e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2420),
                addmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x2400)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2440),
                addmod(
                    mload(add(transcript, 0x2420)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2460),
                mulmod(
                    mload(add(transcript, 0x2440)),
                    mload(add(transcript, 0x23c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2480),
                mulmod(
                    mload(add(transcript, 0x2460)),
                    mload(add(transcript, 0xa40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24a0),
                addmod(
                    mload(add(transcript, 0x2340)),
                    sub(f_q, mload(add(transcript, 0x2480))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24c0),
                mulmod(
                    mload(add(transcript, 0x24a0)),
                    mload(add(transcript, 0x2240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24e0),
                addmod(
                    mload(add(transcript, 0x2160)),
                    mload(add(transcript, 0x24c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2500),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x24e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2520),
                mulmod(
                    mload(add(transcript, 0x9c0)),
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2540),
                addmod(
                    mload(add(transcript, 0x7c0)),
                    mload(add(transcript, 0x2520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2560),
                addmod(
                    mload(add(transcript, 0x2540)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2580),
                mulmod(
                    mload(add(transcript, 0x9e0)),
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25a0),
                addmod(
                    mload(add(transcript, 0x840)),
                    mload(add(transcript, 0x2580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25c0),
                addmod(
                    mload(add(transcript, 0x25a0)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25e0),
                mulmod(
                    mload(add(transcript, 0x25c0)),
                    mload(add(transcript, 0x2560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2600),
                mulmod(
                    mload(add(transcript, 0x25e0)),
                    mload(add(transcript, 0xac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2620),
                mulmod(
                    8910878055287538404433155982483128285667088683464058436815641868457422632747,
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2640),
                mulmod(
                    mload(add(transcript, 0x700)),
                    mload(add(transcript, 0x2620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2660),
                addmod(
                    mload(add(transcript, 0x7c0)),
                    mload(add(transcript, 0x2640)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2680),
                addmod(
                    mload(add(transcript, 0x2660)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26a0),
                mulmod(
                    11166246659983828508719468090013646171463329086121580628794302409516816350802,
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26c0),
                mulmod(
                    mload(add(transcript, 0x700)),
                    mload(add(transcript, 0x26a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26e0),
                addmod(
                    mload(add(transcript, 0x840)),
                    mload(add(transcript, 0x26c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2700),
                addmod(
                    mload(add(transcript, 0x26e0)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2720),
                mulmod(
                    mload(add(transcript, 0x2700)),
                    mload(add(transcript, 0x2680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2740),
                mulmod(
                    mload(add(transcript, 0x2720)),
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2760),
                addmod(
                    mload(add(transcript, 0x2600)),
                    sub(f_q, mload(add(transcript, 0x2740))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2780),
                mulmod(
                    mload(add(transcript, 0x2760)),
                    mload(add(transcript, 0x2240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27a0),
                addmod(
                    mload(add(transcript, 0x2500)),
                    mload(add(transcript, 0x2780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27c0),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x27a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27e0),
                mulmod(
                    mload(add(transcript, 0xa00)),
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2800),
                addmod(
                    mload(add(transcript, 0x8c0)),
                    mload(add(transcript, 0x27e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2820),
                addmod(
                    mload(add(transcript, 0x2800)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2840),
                mulmod(
                    mload(add(transcript, 0xa20)),
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2860),
                addmod(
                    mload(add(transcript, 0x1ca0)),
                    mload(add(transcript, 0x2840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2880),
                addmod(
                    mload(add(transcript, 0x2860)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28a0),
                mulmod(
                    mload(add(transcript, 0x2880)),
                    mload(add(transcript, 0x2820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28c0),
                mulmod(
                    mload(add(transcript, 0x28a0)),
                    mload(add(transcript, 0xb20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28e0),
                mulmod(
                    284840088355319032285349970403338060113257071685626700086398481893096618818,
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2900),
                mulmod(
                    mload(add(transcript, 0x700)),
                    mload(add(transcript, 0x28e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2920),
                addmod(
                    mload(add(transcript, 0x8c0)),
                    mload(add(transcript, 0x2900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2940),
                addmod(
                    mload(add(transcript, 0x2920)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2960),
                mulmod(
                    21134065618345176623193549882539580312263652408302468683943992798037078993309,
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2980),
                mulmod(
                    mload(add(transcript, 0x700)),
                    mload(add(transcript, 0x2960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29a0),
                addmod(
                    mload(add(transcript, 0x1ca0)),
                    mload(add(transcript, 0x2980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29c0),
                addmod(
                    mload(add(transcript, 0x29a0)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29e0),
                mulmod(
                    mload(add(transcript, 0x29c0)),
                    mload(add(transcript, 0x2940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a00),
                mulmod(
                    mload(add(transcript, 0x29e0)),
                    mload(add(transcript, 0xb00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a20),
                addmod(
                    mload(add(transcript, 0x28c0)),
                    sub(f_q, mload(add(transcript, 0x2a00))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a40),
                mulmod(
                    mload(add(transcript, 0x2a20)),
                    mload(add(transcript, 0x2240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a60),
                addmod(
                    mload(add(transcript, 0x27c0)),
                    mload(add(transcript, 0x2a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a80),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x2a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2aa0),
                addmod(1, sub(f_q, mload(add(transcript, 0xb40))), f_q)
            )
            mstore(
                add(transcript, 0x2ac0),
                mulmod(
                    mload(add(transcript, 0x2aa0)),
                    mload(add(transcript, 0x1ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ae0),
                addmod(
                    mload(add(transcript, 0x2a80)),
                    mload(add(transcript, 0x2ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b00),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x2ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b20),
                mulmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b40),
                addmod(
                    mload(add(transcript, 0x2b20)),
                    sub(f_q, mload(add(transcript, 0xb40))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b60),
                mulmod(
                    mload(add(transcript, 0x2b40)),
                    mload(add(transcript, 0x1a00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b80),
                addmod(
                    mload(add(transcript, 0x2b00)),
                    mload(add(transcript, 0x2b60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ba0),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x2b80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2bc0),
                addmod(
                    mload(add(transcript, 0xb80)),
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2be0),
                mulmod(
                    mload(add(transcript, 0x2bc0)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c00),
                addmod(
                    mload(add(transcript, 0xbc0)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c20),
                mulmod(
                    mload(add(transcript, 0x2c00)),
                    mload(add(transcript, 0x2be0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c40),
                addmod(
                    mload(add(transcript, 0x8c0)),
                    mload(add(transcript, 0x3e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c60),
                mulmod(
                    mload(add(transcript, 0x2c40)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c80),
                addmod(
                    mload(add(transcript, 0x900)),
                    mload(add(transcript, 0x440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ca0),
                mulmod(
                    mload(add(transcript, 0x2c80)),
                    mload(add(transcript, 0x2c60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2cc0),
                addmod(
                    mload(add(transcript, 0x2c20)),
                    sub(f_q, mload(add(transcript, 0x2ca0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ce0),
                mulmod(
                    mload(add(transcript, 0x2cc0)),
                    mload(add(transcript, 0x2240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d00),
                addmod(
                    mload(add(transcript, 0x2ba0)),
                    mload(add(transcript, 0x2ce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d20),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x2d00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d40),
                addmod(
                    mload(add(transcript, 0xb80)),
                    sub(f_q, mload(add(transcript, 0xbc0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d60),
                mulmod(
                    mload(add(transcript, 0x2d40)),
                    mload(add(transcript, 0x1ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d80),
                addmod(
                    mload(add(transcript, 0x2d20)),
                    mload(add(transcript, 0x2d60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2da0),
                mulmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x2d80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2dc0),
                mulmod(
                    mload(add(transcript, 0x2d40)),
                    mload(add(transcript, 0x2240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2de0),
                addmod(
                    mload(add(transcript, 0xb80)),
                    sub(f_q, mload(add(transcript, 0xba0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e00),
                mulmod(
                    mload(add(transcript, 0x2de0)),
                    mload(add(transcript, 0x2dc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e20),
                addmod(
                    mload(add(transcript, 0x2da0)),
                    mload(add(transcript, 0x2e00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e40),
                mulmod(
                    mload(add(transcript, 0x10e0)),
                    mload(add(transcript, 0x10e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e60),
                mulmod(
                    mload(add(transcript, 0x2e40)),
                    mload(add(transcript, 0x10e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e80),
                mulmod(1, mload(add(transcript, 0x10e0)), f_q)
            )
            mstore(
                add(transcript, 0x2ea0),
                mulmod(1, mload(add(transcript, 0x2e40)), f_q)
            )
            mstore(
                add(transcript, 0x2ec0),
                mulmod(
                    mload(add(transcript, 0x2e20)),
                    mload(add(transcript, 0x1100)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ee0),
                mulmod(
                    mload(add(transcript, 0xe00)),
                    mload(add(transcript, 0x700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f00),
                mulmod(mload(add(transcript, 0x700)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2f20),
                addmod(
                    mload(add(transcript, 0xd00)),
                    sub(f_q, mload(add(transcript, 0x2f00))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f40),
                mulmod(
                    mload(add(transcript, 0x700)),
                    8374374965308410102411073611984011876711565317741801500439755773472076597347,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f60),
                addmod(
                    mload(add(transcript, 0xd00)),
                    sub(f_q, mload(add(transcript, 0x2f40))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f80),
                mulmod(
                    mload(add(transcript, 0x700)),
                    11451405578697956743456240853980216273390554734748796433026540431386972584651,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fa0),
                addmod(
                    mload(add(transcript, 0xd00)),
                    sub(f_q, mload(add(transcript, 0x2f80))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fc0),
                mulmod(
                    mload(add(transcript, 0x700)),
                    12929131318670223636853686797196826072950305380535537217467769528748593133487,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fe0),
                addmod(
                    mload(add(transcript, 0xd00)),
                    sub(f_q, mload(add(transcript, 0x2fc0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3000),
                mulmod(
                    mload(add(transcript, 0x700)),
                    17329448237240114492580865744088056414251735686965494637158808787419781175510,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3020),
                addmod(
                    mload(add(transcript, 0xd00)),
                    sub(f_q, mload(add(transcript, 0x3000))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3040),
                mulmod(
                    mload(add(transcript, 0x700)),
                    21490807004895109926141140246143262403290679459142140821740925192625185504522,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3060),
                addmod(
                    mload(add(transcript, 0xd00)),
                    sub(f_q, mload(add(transcript, 0x3040))),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0xd00)),
                    6616149745577394522356295102346368305374051634342887004165528916468992151333,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        15272093126261880699890110642910906783174312766073147339532675270106816344284,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x3080), result)
            }
            {
                let result := mulmod(
                    mload(add(transcript, 0xd00)),
                    530501691302793820034524283154921640443166880847115433758691660016816186416,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        6735468303947967792722299167169712601265763928443086612877978228369959138708,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x30a0), result)
            }
            {
                let result := mulmod(
                    mload(add(transcript, 0xd00)),
                    6735468303947967792722299167169712601265763928443086612877978228369959138708,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        21402573809525492531235934453699988060841876665026314791644170130242704768864,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x30c0), result)
            }
            {
                let result := mulmod(
                    mload(add(transcript, 0xd00)),
                    21558793644302942916864965630979640748886316167261336210841195936026980690666,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        21647881284526053590463969745634050372655996593461286860577821962674562513632,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x30e0), result)
            }
            mstore(
                add(transcript, 0x3100),
                mulmod(1, mload(add(transcript, 0x2f20)), f_q)
            )
            mstore(
                add(transcript, 0x3120),
                mulmod(
                    mload(add(transcript, 0x3100)),
                    mload(add(transcript, 0x2fa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3140),
                mulmod(
                    mload(add(transcript, 0x3120)),
                    mload(add(transcript, 0x2f60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3160),
                mulmod(
                    mload(add(transcript, 0x3140)),
                    mload(add(transcript, 0x3060)),
                    f_q
                )
            )
            {
                let result := mulmod(mload(add(transcript, 0xd00)), 1, f_q)
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        21888242871839275222246405745257275088548364400416034343698204186575808495616,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x3180), result)
            }
            {
                let result := mulmod(
                    mload(add(transcript, 0xd00)),
                    12163000419891990293569405173061573680049742717229898748261573253229795914908,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        9725242451947284928677000572195701408498621683186135595436630933346012580709,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x31a0), result)
            }
            {
                let result := mulmod(
                    mload(add(transcript, 0xd00)),
                    17085049131699056766421998221476555826977441931846378573521510030619952504372,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        6337000465755888211746305680664882431492568521396101891532798530745714905908,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x31c0), result)
            }
            {
                let result := mulmod(
                    mload(add(transcript, 0xd00)),
                    10262058425268217215884133263876699099081481632544093361167483234163265012860,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        14297308348282218433797077139696728813764374573836158179437870281950912384055,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x31e0), result)
            }
            mstore(
                add(transcript, 0x3200),
                mulmod(
                    mload(add(transcript, 0x3120)),
                    mload(add(transcript, 0x2fe0)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0xd00)),
                    10436837293141318478790164891277058815157809665667237910671663755188835910967,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        11451405578697956743456240853980216273390554734748796433026540431386972584650,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x3220), result)
            }
            {
                let result := mulmod(
                    mload(add(transcript, 0xd00)),
                    11451405578697956743456240853980216273390554734748796433026540431386972584650,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        3077030613389546641045167241996204396678989417006994932586784657914895987304,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x3240), result)
            }
            {
                let result := mulmod(
                    mload(add(transcript, 0xd00)),
                    4558794634599160729665540001169218674296628713450539706539395399156027320108,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        17329448237240114492580865744088056414251735686965494637158808787419781175509,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x3260), result)
            }
            {
                let result := mulmod(
                    mload(add(transcript, 0xd00)),
                    17329448237240114492580865744088056414251735686965494637158808787419781175509,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x700)),
                        7587894345819650164285585254437911847348718480492193252124775402539837301163,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x3280), result)
            }
            mstore(
                add(transcript, 0x32a0),
                mulmod(
                    mload(add(transcript, 0x3100)),
                    mload(add(transcript, 0x3020)),
                    f_q
                )
            )
            {
                let prod := mload(add(transcript, 0x3080))
                prod := mulmod(mload(add(transcript, 0x30a0)), prod, f_q)
                mstore(add(transcript, 0x32c0), prod)
                prod := mulmod(mload(add(transcript, 0x30c0)), prod, f_q)
                mstore(add(transcript, 0x32e0), prod)
                prod := mulmod(mload(add(transcript, 0x30e0)), prod, f_q)
                mstore(add(transcript, 0x3300), prod)
                prod := mulmod(mload(add(transcript, 0x3180)), prod, f_q)
                mstore(add(transcript, 0x3320), prod)
                prod := mulmod(mload(add(transcript, 0x3100)), prod, f_q)
                mstore(add(transcript, 0x3340), prod)
                prod := mulmod(mload(add(transcript, 0x31a0)), prod, f_q)
                mstore(add(transcript, 0x3360), prod)
                prod := mulmod(mload(add(transcript, 0x31c0)), prod, f_q)
                mstore(add(transcript, 0x3380), prod)
                prod := mulmod(mload(add(transcript, 0x31e0)), prod, f_q)
                mstore(add(transcript, 0x33a0), prod)
                prod := mulmod(mload(add(transcript, 0x3200)), prod, f_q)
                mstore(add(transcript, 0x33c0), prod)
                prod := mulmod(mload(add(transcript, 0x3220)), prod, f_q)
                mstore(add(transcript, 0x33e0), prod)
                prod := mulmod(mload(add(transcript, 0x3240)), prod, f_q)
                mstore(add(transcript, 0x3400), prod)
                prod := mulmod(mload(add(transcript, 0x3120)), prod, f_q)
                mstore(add(transcript, 0x3420), prod)
                prod := mulmod(mload(add(transcript, 0x3260)), prod, f_q)
                mstore(add(transcript, 0x3440), prod)
                prod := mulmod(mload(add(transcript, 0x3280)), prod, f_q)
                mstore(add(transcript, 0x3460), prod)
                prod := mulmod(mload(add(transcript, 0x32a0)), prod, f_q)
                mstore(add(transcript, 0x3480), prod)
            }
            mstore(add(transcript, 0x34c0), 32)
            mstore(add(transcript, 0x34e0), 32)
            mstore(add(transcript, 0x3500), 32)
            mstore(add(transcript, 0x3520), mload(add(transcript, 0x3480)))
            mstore(
                add(transcript, 0x3540),
                21888242871839275222246405745257275088548364400416034343698204186575808495615
            )
            mstore(
                add(transcript, 0x3560),
                21888242871839275222246405745257275088548364400416034343698204186575808495617
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x5,
                        add(transcript, 0x34c0),
                        0xc0,
                        add(transcript, 0x34a0),
                        0x20
                    ),
                    1
                ),
                success
            )
            {
                let inv := mload(add(transcript, 0x34a0))
                let v
                v := mload(add(transcript, 0x32a0))
                mstore(
                    add(transcript, 0x32a0),
                    mulmod(mload(add(transcript, 0x3460)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x3280))
                mstore(
                    add(transcript, 0x3280),
                    mulmod(mload(add(transcript, 0x3440)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x3260))
                mstore(
                    add(transcript, 0x3260),
                    mulmod(mload(add(transcript, 0x3420)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x3120))
                mstore(
                    add(transcript, 0x3120),
                    mulmod(mload(add(transcript, 0x3400)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x3240))
                mstore(
                    add(transcript, 0x3240),
                    mulmod(mload(add(transcript, 0x33e0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x3220))
                mstore(
                    add(transcript, 0x3220),
                    mulmod(mload(add(transcript, 0x33c0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x3200))
                mstore(
                    add(transcript, 0x3200),
                    mulmod(mload(add(transcript, 0x33a0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x31e0))
                mstore(
                    add(transcript, 0x31e0),
                    mulmod(mload(add(transcript, 0x3380)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x31c0))
                mstore(
                    add(transcript, 0x31c0),
                    mulmod(mload(add(transcript, 0x3360)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x31a0))
                mstore(
                    add(transcript, 0x31a0),
                    mulmod(mload(add(transcript, 0x3340)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x3100))
                mstore(
                    add(transcript, 0x3100),
                    mulmod(mload(add(transcript, 0x3320)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x3180))
                mstore(
                    add(transcript, 0x3180),
                    mulmod(mload(add(transcript, 0x3300)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x30e0))
                mstore(
                    add(transcript, 0x30e0),
                    mulmod(mload(add(transcript, 0x32e0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x30c0))
                mstore(
                    add(transcript, 0x30c0),
                    mulmod(mload(add(transcript, 0x32c0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x30a0))
                mstore(
                    add(transcript, 0x30a0),
                    mulmod(mload(add(transcript, 0x3080)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                mstore(add(transcript, 0x3080), inv)
            }
            {
                let result := mload(add(transcript, 0x3080))
                result := addmod(mload(add(transcript, 0x30a0)), result, f_q)
                result := addmod(mload(add(transcript, 0x30c0)), result, f_q)
                result := addmod(mload(add(transcript, 0x30e0)), result, f_q)
                mstore(add(transcript, 0x3580), result)
            }
            mstore(
                add(transcript, 0x35a0),
                mulmod(
                    mload(add(transcript, 0x3160)),
                    mload(add(transcript, 0x3100)),
                    f_q
                )
            )
            {
                let result := mload(add(transcript, 0x3180))
                mstore(add(transcript, 0x35c0), result)
            }
            mstore(
                add(transcript, 0x35e0),
                mulmod(
                    mload(add(transcript, 0x3160)),
                    mload(add(transcript, 0x3200)),
                    f_q
                )
            )
            {
                let result := mload(add(transcript, 0x31a0))
                result := addmod(mload(add(transcript, 0x31c0)), result, f_q)
                result := addmod(mload(add(transcript, 0x31e0)), result, f_q)
                mstore(add(transcript, 0x3600), result)
            }
            mstore(
                add(transcript, 0x3620),
                mulmod(
                    mload(add(transcript, 0x3160)),
                    mload(add(transcript, 0x3120)),
                    f_q
                )
            )
            {
                let result := mload(add(transcript, 0x3220))
                result := addmod(mload(add(transcript, 0x3240)), result, f_q)
                mstore(add(transcript, 0x3640), result)
            }
            mstore(
                add(transcript, 0x3660),
                mulmod(
                    mload(add(transcript, 0x3160)),
                    mload(add(transcript, 0x32a0)),
                    f_q
                )
            )
            {
                let result := mload(add(transcript, 0x3260))
                result := addmod(mload(add(transcript, 0x3280)), result, f_q)
                mstore(add(transcript, 0x3680), result)
            }
            {
                let prod := mload(add(transcript, 0x3580))
                prod := mulmod(mload(add(transcript, 0x35c0)), prod, f_q)
                mstore(add(transcript, 0x36a0), prod)
                prod := mulmod(mload(add(transcript, 0x3600)), prod, f_q)
                mstore(add(transcript, 0x36c0), prod)
                prod := mulmod(mload(add(transcript, 0x3640)), prod, f_q)
                mstore(add(transcript, 0x36e0), prod)
                prod := mulmod(mload(add(transcript, 0x3680)), prod, f_q)
                mstore(add(transcript, 0x3700), prod)
            }
            mstore(add(transcript, 0x3740), 32)
            mstore(add(transcript, 0x3760), 32)
            mstore(add(transcript, 0x3780), 32)
            mstore(add(transcript, 0x37a0), mload(add(transcript, 0x3700)))
            mstore(
                add(transcript, 0x37c0),
                21888242871839275222246405745257275088548364400416034343698204186575808495615
            )
            mstore(
                add(transcript, 0x37e0),
                21888242871839275222246405745257275088548364400416034343698204186575808495617
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x5,
                        add(transcript, 0x3740),
                        0xc0,
                        add(transcript, 0x3720),
                        0x20
                    ),
                    1
                ),
                success
            )
            {
                let inv := mload(add(transcript, 0x3720))
                let v
                v := mload(add(transcript, 0x3680))
                mstore(
                    add(transcript, 0x3680),
                    mulmod(mload(add(transcript, 0x36e0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x3640))
                mstore(
                    add(transcript, 0x3640),
                    mulmod(mload(add(transcript, 0x36c0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x3600))
                mstore(
                    add(transcript, 0x3600),
                    mulmod(mload(add(transcript, 0x36a0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x35c0))
                mstore(
                    add(transcript, 0x35c0),
                    mulmod(mload(add(transcript, 0x3580)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                mstore(add(transcript, 0x3580), inv)
            }
            mstore(
                add(transcript, 0x3800),
                mulmod(
                    mload(add(transcript, 0x35a0)),
                    mload(add(transcript, 0x35c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3820),
                mulmod(
                    mload(add(transcript, 0x35e0)),
                    mload(add(transcript, 0x3600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3840),
                mulmod(
                    mload(add(transcript, 0x3620)),
                    mload(add(transcript, 0x3640)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3860),
                mulmod(
                    mload(add(transcript, 0x3660)),
                    mload(add(transcript, 0x3680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3880),
                mulmod(
                    mload(add(transcript, 0xc00)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38a0),
                mulmod(
                    mload(add(transcript, 0x3880)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38c0),
                mulmod(
                    mload(add(transcript, 0x38a0)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38e0),
                mulmod(
                    mload(add(transcript, 0x38c0)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3900),
                mulmod(
                    mload(add(transcript, 0x38e0)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3920),
                mulmod(
                    mload(add(transcript, 0x3900)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3940),
                mulmod(
                    mload(add(transcript, 0x3920)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3960),
                mulmod(
                    mload(add(transcript, 0x3940)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3980),
                mulmod(
                    mload(add(transcript, 0x3960)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39a0),
                mulmod(
                    mload(add(transcript, 0x3980)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39c0),
                mulmod(
                    mload(add(transcript, 0x39a0)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39e0),
                mulmod(
                    mload(add(transcript, 0x39c0)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a00),
                mulmod(
                    mload(add(transcript, 0x39e0)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a20),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a40),
                mulmod(
                    mload(add(transcript, 0x3a20)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a60),
                mulmod(
                    mload(add(transcript, 0x3a40)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a80),
                mulmod(
                    mload(add(transcript, 0x3a60)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x3080)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x760)),
                        mload(add(transcript, 0x30a0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x780)),
                        mload(add(transcript, 0x30c0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x7a0)),
                        mload(add(transcript, 0x30e0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x3aa0), result)
            }
            mstore(
                add(transcript, 0x3ac0),
                mulmod(
                    mload(add(transcript, 0x3aa0)),
                    mload(add(transcript, 0x3580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ae0),
                mulmod(sub(f_q, mload(add(transcript, 0x3ac0))), 1, f_q)
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x7c0)),
                    mload(add(transcript, 0x3080)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x7e0)),
                        mload(add(transcript, 0x30a0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x800)),
                        mload(add(transcript, 0x30c0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x820)),
                        mload(add(transcript, 0x30e0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x3b00), result)
            }
            mstore(
                add(transcript, 0x3b20),
                mulmod(
                    mload(add(transcript, 0x3b00)),
                    mload(add(transcript, 0x3580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b40),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x3b20))),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b60),
                mulmod(1, mload(add(transcript, 0xc00)), f_q)
            )
            mstore(
                add(transcript, 0x3b80),
                addmod(
                    mload(add(transcript, 0x3ae0)),
                    mload(add(transcript, 0x3b40)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x840)),
                    mload(add(transcript, 0x3080)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x860)),
                        mload(add(transcript, 0x30a0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x880)),
                        mload(add(transcript, 0x30c0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x8a0)),
                        mload(add(transcript, 0x30e0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x3ba0), result)
            }
            mstore(
                add(transcript, 0x3bc0),
                mulmod(
                    mload(add(transcript, 0x3ba0)),
                    mload(add(transcript, 0x3580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3be0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x3bc0))),
                    mload(add(transcript, 0x3880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c00),
                mulmod(1, mload(add(transcript, 0x3880)), f_q)
            )
            mstore(
                add(transcript, 0x3c20),
                addmod(
                    mload(add(transcript, 0x3b80)),
                    mload(add(transcript, 0x3be0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c40),
                mulmod(mload(add(transcript, 0x3c20)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3c60),
                mulmod(mload(add(transcript, 0x3b60)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3c80),
                mulmod(mload(add(transcript, 0x3c00)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3ca0),
                mulmod(1, mload(add(transcript, 0x35a0)), f_q)
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x8c0)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x3cc0), result)
            }
            mstore(
                add(transcript, 0x3ce0),
                mulmod(
                    mload(add(transcript, 0x3cc0)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d00),
                mulmod(sub(f_q, mload(add(transcript, 0x3ce0))), 1, f_q)
            )
            mstore(
                add(transcript, 0x3d20),
                mulmod(mload(add(transcript, 0x3ca0)), 1, f_q)
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0xbc0)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x3d40), result)
            }
            mstore(
                add(transcript, 0x3d60),
                mulmod(
                    mload(add(transcript, 0x3d40)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d80),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x3d60))),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3da0),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3dc0),
                addmod(
                    mload(add(transcript, 0x3d00)),
                    mload(add(transcript, 0x3d80)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x8e0)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x3de0), result)
            }
            mstore(
                add(transcript, 0x3e00),
                mulmod(
                    mload(add(transcript, 0x3de0)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e20),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x3e00))),
                    mload(add(transcript, 0x3880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e40),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x3880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e60),
                addmod(
                    mload(add(transcript, 0x3dc0)),
                    mload(add(transcript, 0x3e20)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x900)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x3e80), result)
            }
            mstore(
                add(transcript, 0x3ea0),
                mulmod(
                    mload(add(transcript, 0x3e80)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ec0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x3ea0))),
                    mload(add(transcript, 0x38a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ee0),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x38a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f00),
                addmod(
                    mload(add(transcript, 0x3e60)),
                    mload(add(transcript, 0x3ec0)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x920)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x3f20), result)
            }
            mstore(
                add(transcript, 0x3f40),
                mulmod(
                    mload(add(transcript, 0x3f20)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f60),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x3f40))),
                    mload(add(transcript, 0x38c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f80),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x38c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3fa0),
                addmod(
                    mload(add(transcript, 0x3f00)),
                    mload(add(transcript, 0x3f60)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x3fc0), result)
            }
            mstore(
                add(transcript, 0x3fe0),
                mulmod(
                    mload(add(transcript, 0x3fc0)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4000),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x3fe0))),
                    mload(add(transcript, 0x38e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4020),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x38e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4040),
                addmod(
                    mload(add(transcript, 0x3fa0)),
                    mload(add(transcript, 0x4000)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x980)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x4060), result)
            }
            mstore(
                add(transcript, 0x4080),
                mulmod(
                    mload(add(transcript, 0x4060)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x40a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x4080))),
                    mload(add(transcript, 0x3900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x40c0),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x3900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x40e0),
                addmod(
                    mload(add(transcript, 0x4040)),
                    mload(add(transcript, 0x40a0)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x9a0)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x4100), result)
            }
            mstore(
                add(transcript, 0x4120),
                mulmod(
                    mload(add(transcript, 0x4100)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4140),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x4120))),
                    mload(add(transcript, 0x3920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4160),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x3920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4180),
                addmod(
                    mload(add(transcript, 0x40e0)),
                    mload(add(transcript, 0x4140)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x9c0)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x41a0), result)
            }
            mstore(
                add(transcript, 0x41c0),
                mulmod(
                    mload(add(transcript, 0x41a0)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x41e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x41c0))),
                    mload(add(transcript, 0x3940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4200),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x3940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4220),
                addmod(
                    mload(add(transcript, 0x4180)),
                    mload(add(transcript, 0x41e0)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x9e0)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x4240), result)
            }
            mstore(
                add(transcript, 0x4260),
                mulmod(
                    mload(add(transcript, 0x4240)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4280),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x4260))),
                    mload(add(transcript, 0x3960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x42a0),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x3960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x42c0),
                addmod(
                    mload(add(transcript, 0x4220)),
                    mload(add(transcript, 0x4280)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0xa00)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x42e0), result)
            }
            mstore(
                add(transcript, 0x4300),
                mulmod(
                    mload(add(transcript, 0x42e0)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4320),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x4300))),
                    mload(add(transcript, 0x3980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4340),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x3980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4360),
                addmod(
                    mload(add(transcript, 0x42c0)),
                    mload(add(transcript, 0x4320)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0xa20)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x4380), result)
            }
            mstore(
                add(transcript, 0x43a0),
                mulmod(
                    mload(add(transcript, 0x4380)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x43c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x43a0))),
                    mload(add(transcript, 0x39a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x43e0),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x39a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4400),
                addmod(
                    mload(add(transcript, 0x4360)),
                    mload(add(transcript, 0x43c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4420),
                mulmod(
                    mload(add(transcript, 0x2e80)),
                    mload(add(transcript, 0x35a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4440),
                mulmod(
                    mload(add(transcript, 0x2ea0)),
                    mload(add(transcript, 0x35a0)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x2ec0)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x4460), result)
            }
            mstore(
                add(transcript, 0x4480),
                mulmod(
                    mload(add(transcript, 0x4460)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x44a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x4480))),
                    mload(add(transcript, 0x39c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x44c0),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x39c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x44e0),
                mulmod(
                    mload(add(transcript, 0x4420)),
                    mload(add(transcript, 0x39c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4500),
                mulmod(
                    mload(add(transcript, 0x4440)),
                    mload(add(transcript, 0x39c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4520),
                addmod(
                    mload(add(transcript, 0x4400)),
                    mload(add(transcript, 0x44a0)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x960)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
                mstore(add(transcript, 0x4540), result)
            }
            mstore(
                add(transcript, 0x4560),
                mulmod(
                    mload(add(transcript, 0x4540)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4580),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x4560))),
                    mload(add(transcript, 0x39e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x45a0),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x39e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x45c0),
                addmod(
                    mload(add(transcript, 0x4520)),
                    mload(add(transcript, 0x4580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x45e0),
                mulmod(
                    mload(add(transcript, 0x45c0)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4600),
                mulmod(
                    mload(add(transcript, 0x3d20)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4620),
                mulmod(
                    mload(add(transcript, 0x3da0)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4640),
                mulmod(
                    mload(add(transcript, 0x3e40)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4660),
                mulmod(
                    mload(add(transcript, 0x3ee0)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4680),
                mulmod(
                    mload(add(transcript, 0x3f80)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x46a0),
                mulmod(
                    mload(add(transcript, 0x4020)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x46c0),
                mulmod(
                    mload(add(transcript, 0x40c0)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x46e0),
                mulmod(
                    mload(add(transcript, 0x4160)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4700),
                mulmod(
                    mload(add(transcript, 0x4200)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4720),
                mulmod(
                    mload(add(transcript, 0x42a0)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4740),
                mulmod(
                    mload(add(transcript, 0x4340)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4760),
                mulmod(
                    mload(add(transcript, 0x43e0)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4780),
                mulmod(
                    mload(add(transcript, 0x44c0)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x47a0),
                mulmod(
                    mload(add(transcript, 0x44e0)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x47c0),
                mulmod(
                    mload(add(transcript, 0x4500)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x47e0),
                mulmod(
                    mload(add(transcript, 0x45a0)),
                    mload(add(transcript, 0xc60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4800),
                addmod(
                    mload(add(transcript, 0x3c40)),
                    mload(add(transcript, 0x45e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4820),
                mulmod(1, mload(add(transcript, 0x35e0)), f_q)
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0xa40)),
                    mload(add(transcript, 0x31a0)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0xa60)),
                        mload(add(transcript, 0x31c0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0xa80)),
                        mload(add(transcript, 0x31e0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x4840), result)
            }
            mstore(
                add(transcript, 0x4860),
                mulmod(
                    mload(add(transcript, 0x4840)),
                    mload(add(transcript, 0x3820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4880),
                mulmod(sub(f_q, mload(add(transcript, 0x4860))), 1, f_q)
            )
            mstore(
                add(transcript, 0x48a0),
                mulmod(mload(add(transcript, 0x4820)), 1, f_q)
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0x31a0)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0xac0)),
                        mload(add(transcript, 0x31c0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0xae0)),
                        mload(add(transcript, 0x31e0)),
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
                    mload(add(transcript, 0x48c0)),
                    mload(add(transcript, 0x3820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4900),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x48e0))),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4920),
                mulmod(
                    mload(add(transcript, 0x4820)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4940),
                addmod(
                    mload(add(transcript, 0x4880)),
                    mload(add(transcript, 0x4900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4960),
                mulmod(
                    mload(add(transcript, 0x4940)),
                    mload(add(transcript, 0x3a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4980),
                mulmod(
                    mload(add(transcript, 0x48a0)),
                    mload(add(transcript, 0x3a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x49a0),
                mulmod(
                    mload(add(transcript, 0x4920)),
                    mload(add(transcript, 0x3a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x49c0),
                addmod(
                    mload(add(transcript, 0x4800)),
                    mload(add(transcript, 0x4960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x49e0),
                mulmod(1, mload(add(transcript, 0x3620)), f_q)
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0x3220)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0xb20)),
                        mload(add(transcript, 0x3240)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x4a00), result)
            }
            mstore(
                add(transcript, 0x4a20),
                mulmod(
                    mload(add(transcript, 0x4a00)),
                    mload(add(transcript, 0x3840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4a40),
                mulmod(sub(f_q, mload(add(transcript, 0x4a20))), 1, f_q)
            )
            mstore(
                add(transcript, 0x4a60),
                mulmod(mload(add(transcript, 0x49e0)), 1, f_q)
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0x3220)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0xb60)),
                        mload(add(transcript, 0x3240)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x4a80), result)
            }
            mstore(
                add(transcript, 0x4aa0),
                mulmod(
                    mload(add(transcript, 0x4a80)),
                    mload(add(transcript, 0x3840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ac0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x4aa0))),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ae0),
                mulmod(
                    mload(add(transcript, 0x49e0)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4b00),
                addmod(
                    mload(add(transcript, 0x4a40)),
                    mload(add(transcript, 0x4ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4b20),
                mulmod(
                    mload(add(transcript, 0x4b00)),
                    mload(add(transcript, 0x3a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4b40),
                mulmod(
                    mload(add(transcript, 0x4a60)),
                    mload(add(transcript, 0x3a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4b60),
                mulmod(
                    mload(add(transcript, 0x4ae0)),
                    mload(add(transcript, 0x3a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4b80),
                addmod(
                    mload(add(transcript, 0x49c0)),
                    mload(add(transcript, 0x4b20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ba0),
                mulmod(1, mload(add(transcript, 0x3660)), f_q)
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0xb80)),
                    mload(add(transcript, 0x3260)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0xba0)),
                        mload(add(transcript, 0x3280)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x4bc0), result)
            }
            mstore(
                add(transcript, 0x4be0),
                mulmod(
                    mload(add(transcript, 0x4bc0)),
                    mload(add(transcript, 0x3860)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4c00),
                mulmod(sub(f_q, mload(add(transcript, 0x4be0))), 1, f_q)
            )
            mstore(
                add(transcript, 0x4c20),
                mulmod(mload(add(transcript, 0x4ba0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x4c40),
                mulmod(
                    mload(add(transcript, 0x4c00)),
                    mload(add(transcript, 0x3a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4c60),
                mulmod(
                    mload(add(transcript, 0x4c20)),
                    mload(add(transcript, 0x3a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4c80),
                addmod(
                    mload(add(transcript, 0x4b80)),
                    mload(add(transcript, 0x4c40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4ca0),
                mulmod(1, mload(add(transcript, 0x3160)), f_q)
            )
            mstore(
                add(transcript, 0x4cc0),
                mulmod(1, mload(add(transcript, 0xd00)), f_q)
            )
            mstore(
                add(transcript, 0x4ce0),
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            mstore(
                add(transcript, 0x4d00),
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            mstore(add(transcript, 0x4d20), mload(add(transcript, 0x4c80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4ce0),
                        0x60,
                        add(transcript, 0x4ce0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4d40), mload(add(transcript, 0x4ce0)))
            mstore(add(transcript, 0x4d60), mload(add(transcript, 0x4d00)))
            mstore(add(transcript, 0x4d80), mload(add(transcript, 0x1e0)))
            mstore(add(transcript, 0x4da0), mload(add(transcript, 0x200)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4d40),
                        0x80,
                        add(transcript, 0x4d40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4dc0), mload(add(transcript, 0x220)))
            mstore(add(transcript, 0x4de0), mload(add(transcript, 0x240)))
            mstore(add(transcript, 0x4e00), mload(add(transcript, 0x3c60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4dc0),
                        0x60,
                        add(transcript, 0x4dc0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4e20), mload(add(transcript, 0x4d40)))
            mstore(add(transcript, 0x4e40), mload(add(transcript, 0x4d60)))
            mstore(add(transcript, 0x4e60), mload(add(transcript, 0x4dc0)))
            mstore(add(transcript, 0x4e80), mload(add(transcript, 0x4de0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4e20),
                        0x80,
                        add(transcript, 0x4e20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4ea0), mload(add(transcript, 0x260)))
            mstore(add(transcript, 0x4ec0), mload(add(transcript, 0x280)))
            mstore(add(transcript, 0x4ee0), mload(add(transcript, 0x3c80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4ea0),
                        0x60,
                        add(transcript, 0x4ea0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4f00), mload(add(transcript, 0x4e20)))
            mstore(add(transcript, 0x4f20), mload(add(transcript, 0x4e40)))
            mstore(add(transcript, 0x4f40), mload(add(transcript, 0x4ea0)))
            mstore(add(transcript, 0x4f60), mload(add(transcript, 0x4ec0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4f00),
                        0x80,
                        add(transcript, 0x4f00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4f80), mload(add(transcript, 0x2a0)))
            mstore(add(transcript, 0x4fa0), mload(add(transcript, 0x2c0)))
            mstore(add(transcript, 0x4fc0), mload(add(transcript, 0x4600)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4f80),
                        0x60,
                        add(transcript, 0x4f80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4fe0), mload(add(transcript, 0x4f00)))
            mstore(add(transcript, 0x5000), mload(add(transcript, 0x4f20)))
            mstore(add(transcript, 0x5020), mload(add(transcript, 0x4f80)))
            mstore(add(transcript, 0x5040), mload(add(transcript, 0x4fa0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4fe0),
                        0x80,
                        add(transcript, 0x4fe0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5060), mload(add(transcript, 0x380)))
            mstore(add(transcript, 0x5080), mload(add(transcript, 0x3a0)))
            mstore(add(transcript, 0x50a0), mload(add(transcript, 0x4620)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5060),
                        0x60,
                        add(transcript, 0x5060),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x50c0), mload(add(transcript, 0x4fe0)))
            mstore(add(transcript, 0x50e0), mload(add(transcript, 0x5000)))
            mstore(add(transcript, 0x5100), mload(add(transcript, 0x5060)))
            mstore(add(transcript, 0x5120), mload(add(transcript, 0x5080)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x50c0),
                        0x80,
                        add(transcript, 0x50c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5140),
                0x11616573a278c2a5ce87f1a8b1b187026aede85db41c1593944d1b14479a01b1
            )
            mstore(
                add(transcript, 0x5160),
                0x18ba22a3ca2d1755ddd28f06e2b2cf93cb439b5eab7ec73ef6702e2f035c3098
            )
            mstore(add(transcript, 0x5180), mload(add(transcript, 0x4640)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5140),
                        0x60,
                        add(transcript, 0x5140),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x51a0), mload(add(transcript, 0x50c0)))
            mstore(add(transcript, 0x51c0), mload(add(transcript, 0x50e0)))
            mstore(add(transcript, 0x51e0), mload(add(transcript, 0x5140)))
            mstore(add(transcript, 0x5200), mload(add(transcript, 0x5160)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x51a0),
                        0x80,
                        add(transcript, 0x51a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5220),
                0x248957605e6f0a9881ec2c4a375e8898dc8e6ce1f1bfb4ff6abd470567f7ce62
            )
            mstore(
                add(transcript, 0x5240),
                0x0dae09ba53352990ed2e4c8d4bf920465eb536adc193bf348be452950324c2a5
            )
            mstore(add(transcript, 0x5260), mload(add(transcript, 0x4660)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5220),
                        0x60,
                        add(transcript, 0x5220),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5280), mload(add(transcript, 0x51a0)))
            mstore(add(transcript, 0x52a0), mload(add(transcript, 0x51c0)))
            mstore(add(transcript, 0x52c0), mload(add(transcript, 0x5220)))
            mstore(add(transcript, 0x52e0), mload(add(transcript, 0x5240)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5280),
                        0x80,
                        add(transcript, 0x5280),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5300),
                0x293714dc41f636976ced4b2e5eebc0d8b5bfa550be226d23034f8fac839e8016
            )
            mstore(
                add(transcript, 0x5320),
                0x1c33b3e39cc7da64d258b3a2c5397a416eac7c04afd3b0f06b711eeeca4e8667
            )
            mstore(add(transcript, 0x5340), mload(add(transcript, 0x4680)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5300),
                        0x60,
                        add(transcript, 0x5300),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5360), mload(add(transcript, 0x5280)))
            mstore(add(transcript, 0x5380), mload(add(transcript, 0x52a0)))
            mstore(add(transcript, 0x53a0), mload(add(transcript, 0x5300)))
            mstore(add(transcript, 0x53c0), mload(add(transcript, 0x5320)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5360),
                        0x80,
                        add(transcript, 0x5360),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x53e0),
                0x0cf7f734e9511f4338c82bc11d36fe4239a9d0917190b5151092f2036f0a4858
            )
            mstore(
                add(transcript, 0x5400),
                0x2fb986f8afc0c42608c5621b3427bac3bd4873d276edd093c497b4f36efa71ed
            )
            mstore(add(transcript, 0x5420), mload(add(transcript, 0x46a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x53e0),
                        0x60,
                        add(transcript, 0x53e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5440), mload(add(transcript, 0x5360)))
            mstore(add(transcript, 0x5460), mload(add(transcript, 0x5380)))
            mstore(add(transcript, 0x5480), mload(add(transcript, 0x53e0)))
            mstore(add(transcript, 0x54a0), mload(add(transcript, 0x5400)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5440),
                        0x80,
                        add(transcript, 0x5440),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x54c0),
                0x1223f8ee426dbcc5d38aa2381248b872844ebafe3e2578dfa3f2561a6a203cf1
            )
            mstore(
                add(transcript, 0x54e0),
                0x02f430d933d6fadb49de1a9168088540883e1f8c80a64233982a8a15da4ef581
            )
            mstore(add(transcript, 0x5500), mload(add(transcript, 0x46c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x54c0),
                        0x60,
                        add(transcript, 0x54c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5520), mload(add(transcript, 0x5440)))
            mstore(add(transcript, 0x5540), mload(add(transcript, 0x5460)))
            mstore(add(transcript, 0x5560), mload(add(transcript, 0x54c0)))
            mstore(add(transcript, 0x5580), mload(add(transcript, 0x54e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5520),
                        0x80,
                        add(transcript, 0x5520),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x55a0),
                0x05bdeabd162252a92826a64b29db064fbda724a0f62ed05e5390ddca77a92ff4
            )
            mstore(
                add(transcript, 0x55c0),
                0x0c895832072bd227cea4cc4e228a58ca742a58d08c11095b6ed17d04c70d6fa8
            )
            mstore(add(transcript, 0x55e0), mload(add(transcript, 0x46e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x55a0),
                        0x60,
                        add(transcript, 0x55a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5600), mload(add(transcript, 0x5520)))
            mstore(add(transcript, 0x5620), mload(add(transcript, 0x5540)))
            mstore(add(transcript, 0x5640), mload(add(transcript, 0x55a0)))
            mstore(add(transcript, 0x5660), mload(add(transcript, 0x55c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5600),
                        0x80,
                        add(transcript, 0x5600),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5680),
                0x090099641166609115710154de30cd4341f3be85aac2628ff0e672b8812ffe65
            )
            mstore(
                add(transcript, 0x56a0),
                0x09026d6133ef65e173db878b1d00c24badb570e1210b789863f7d7975edd24a3
            )
            mstore(add(transcript, 0x56c0), mload(add(transcript, 0x4700)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5680),
                        0x60,
                        add(transcript, 0x5680),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x56e0), mload(add(transcript, 0x5600)))
            mstore(add(transcript, 0x5700), mload(add(transcript, 0x5620)))
            mstore(add(transcript, 0x5720), mload(add(transcript, 0x5680)))
            mstore(add(transcript, 0x5740), mload(add(transcript, 0x56a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x56e0),
                        0x80,
                        add(transcript, 0x56e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5760),
                0x0508bd933159f8c13b7c790d7c4fe5fad9e19206e8399bde7730b7bd792d8df0
            )
            mstore(
                add(transcript, 0x5780),
                0x0d9e81c9c1f8839c882eb3a2c82e0244ad8dd28d0dcaa961f13888049a86a6c8
            )
            mstore(add(transcript, 0x57a0), mload(add(transcript, 0x4720)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5760),
                        0x60,
                        add(transcript, 0x5760),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x57c0), mload(add(transcript, 0x56e0)))
            mstore(add(transcript, 0x57e0), mload(add(transcript, 0x5700)))
            mstore(add(transcript, 0x5800), mload(add(transcript, 0x5760)))
            mstore(add(transcript, 0x5820), mload(add(transcript, 0x5780)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x57c0),
                        0x80,
                        add(transcript, 0x57c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5840),
                0x2633d792636a9b57029baad6294a6aaf7a1760acb3fd6f81826d4b67337a79aa
            )
            mstore(
                add(transcript, 0x5860),
                0x260173fb515928e0ab10be7e7b5ce0110220de5d4798c8da5409f2f8cad010fd
            )
            mstore(add(transcript, 0x5880), mload(add(transcript, 0x4740)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5840),
                        0x60,
                        add(transcript, 0x5840),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x58a0), mload(add(transcript, 0x57c0)))
            mstore(add(transcript, 0x58c0), mload(add(transcript, 0x57e0)))
            mstore(add(transcript, 0x58e0), mload(add(transcript, 0x5840)))
            mstore(add(transcript, 0x5900), mload(add(transcript, 0x5860)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x58a0),
                        0x80,
                        add(transcript, 0x58a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5920),
                0x0e8279d601b9ac4effdeb65564f8bb392b3ccc25d4c1717a514832759c682e7c
            )
            mstore(
                add(transcript, 0x5940),
                0x07e1fa4e4bc8703d9469cc112e02ccd004e9d1417205a07d839c033a3eb36f4b
            )
            mstore(add(transcript, 0x5960), mload(add(transcript, 0x4760)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5920),
                        0x60,
                        add(transcript, 0x5920),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5980), mload(add(transcript, 0x58a0)))
            mstore(add(transcript, 0x59a0), mload(add(transcript, 0x58c0)))
            mstore(add(transcript, 0x59c0), mload(add(transcript, 0x5920)))
            mstore(add(transcript, 0x59e0), mload(add(transcript, 0x5940)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5980),
                        0x80,
                        add(transcript, 0x5980),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5a00), mload(add(transcript, 0x620)))
            mstore(add(transcript, 0x5a20), mload(add(transcript, 0x640)))
            mstore(add(transcript, 0x5a40), mload(add(transcript, 0x4780)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5a00),
                        0x60,
                        add(transcript, 0x5a00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5a60), mload(add(transcript, 0x5980)))
            mstore(add(transcript, 0x5a80), mload(add(transcript, 0x59a0)))
            mstore(add(transcript, 0x5aa0), mload(add(transcript, 0x5a00)))
            mstore(add(transcript, 0x5ac0), mload(add(transcript, 0x5a20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5a60),
                        0x80,
                        add(transcript, 0x5a60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5ae0), mload(add(transcript, 0x660)))
            mstore(add(transcript, 0x5b00), mload(add(transcript, 0x680)))
            mstore(add(transcript, 0x5b20), mload(add(transcript, 0x47a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5ae0),
                        0x60,
                        add(transcript, 0x5ae0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5b40), mload(add(transcript, 0x5a60)))
            mstore(add(transcript, 0x5b60), mload(add(transcript, 0x5a80)))
            mstore(add(transcript, 0x5b80), mload(add(transcript, 0x5ae0)))
            mstore(add(transcript, 0x5ba0), mload(add(transcript, 0x5b00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5b40),
                        0x80,
                        add(transcript, 0x5b40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5bc0), mload(add(transcript, 0x6a0)))
            mstore(add(transcript, 0x5be0), mload(add(transcript, 0x6c0)))
            mstore(add(transcript, 0x5c00), mload(add(transcript, 0x47c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5bc0),
                        0x60,
                        add(transcript, 0x5bc0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5c20), mload(add(transcript, 0x5b40)))
            mstore(add(transcript, 0x5c40), mload(add(transcript, 0x5b60)))
            mstore(add(transcript, 0x5c60), mload(add(transcript, 0x5bc0)))
            mstore(add(transcript, 0x5c80), mload(add(transcript, 0x5be0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5c20),
                        0x80,
                        add(transcript, 0x5c20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5ca0), mload(add(transcript, 0x580)))
            mstore(add(transcript, 0x5cc0), mload(add(transcript, 0x5a0)))
            mstore(add(transcript, 0x5ce0), mload(add(transcript, 0x47e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5ca0),
                        0x60,
                        add(transcript, 0x5ca0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5d00), mload(add(transcript, 0x5c20)))
            mstore(add(transcript, 0x5d20), mload(add(transcript, 0x5c40)))
            mstore(add(transcript, 0x5d40), mload(add(transcript, 0x5ca0)))
            mstore(add(transcript, 0x5d60), mload(add(transcript, 0x5cc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5d00),
                        0x80,
                        add(transcript, 0x5d00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5d80), mload(add(transcript, 0x480)))
            mstore(add(transcript, 0x5da0), mload(add(transcript, 0x4a0)))
            mstore(add(transcript, 0x5dc0), mload(add(transcript, 0x4980)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5d80),
                        0x60,
                        add(transcript, 0x5d80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5de0), mload(add(transcript, 0x5d00)))
            mstore(add(transcript, 0x5e00), mload(add(transcript, 0x5d20)))
            mstore(add(transcript, 0x5e20), mload(add(transcript, 0x5d80)))
            mstore(add(transcript, 0x5e40), mload(add(transcript, 0x5da0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5de0),
                        0x80,
                        add(transcript, 0x5de0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5e60), mload(add(transcript, 0x4c0)))
            mstore(add(transcript, 0x5e80), mload(add(transcript, 0x4e0)))
            mstore(add(transcript, 0x5ea0), mload(add(transcript, 0x49a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5e60),
                        0x60,
                        add(transcript, 0x5e60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5ec0), mload(add(transcript, 0x5de0)))
            mstore(add(transcript, 0x5ee0), mload(add(transcript, 0x5e00)))
            mstore(add(transcript, 0x5f00), mload(add(transcript, 0x5e60)))
            mstore(add(transcript, 0x5f20), mload(add(transcript, 0x5e80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5ec0),
                        0x80,
                        add(transcript, 0x5ec0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5f40), mload(add(transcript, 0x500)))
            mstore(add(transcript, 0x5f60), mload(add(transcript, 0x520)))
            mstore(add(transcript, 0x5f80), mload(add(transcript, 0x4b40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5f40),
                        0x60,
                        add(transcript, 0x5f40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5fa0), mload(add(transcript, 0x5ec0)))
            mstore(add(transcript, 0x5fc0), mload(add(transcript, 0x5ee0)))
            mstore(add(transcript, 0x5fe0), mload(add(transcript, 0x5f40)))
            mstore(add(transcript, 0x6000), mload(add(transcript, 0x5f60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5fa0),
                        0x80,
                        add(transcript, 0x5fa0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6020), mload(add(transcript, 0x540)))
            mstore(add(transcript, 0x6040), mload(add(transcript, 0x560)))
            mstore(add(transcript, 0x6060), mload(add(transcript, 0x4b60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6020),
                        0x60,
                        add(transcript, 0x6020),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6080), mload(add(transcript, 0x5fa0)))
            mstore(add(transcript, 0x60a0), mload(add(transcript, 0x5fc0)))
            mstore(add(transcript, 0x60c0), mload(add(transcript, 0x6020)))
            mstore(add(transcript, 0x60e0), mload(add(transcript, 0x6040)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6080),
                        0x80,
                        add(transcript, 0x6080),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6100), mload(add(transcript, 0x340)))
            mstore(add(transcript, 0x6120), mload(add(transcript, 0x360)))
            mstore(add(transcript, 0x6140), mload(add(transcript, 0x4c60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6100),
                        0x60,
                        add(transcript, 0x6100),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6160), mload(add(transcript, 0x6080)))
            mstore(add(transcript, 0x6180), mload(add(transcript, 0x60a0)))
            mstore(add(transcript, 0x61a0), mload(add(transcript, 0x6100)))
            mstore(add(transcript, 0x61c0), mload(add(transcript, 0x6120)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6160),
                        0x80,
                        add(transcript, 0x6160),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x61e0), mload(add(transcript, 0xca0)))
            mstore(add(transcript, 0x6200), mload(add(transcript, 0xcc0)))
            mstore(
                add(transcript, 0x6220),
                sub(f_q, mload(add(transcript, 0x4ca0)))
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x61e0),
                        0x60,
                        add(transcript, 0x61e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6240), mload(add(transcript, 0x6160)))
            mstore(add(transcript, 0x6260), mload(add(transcript, 0x6180)))
            mstore(add(transcript, 0x6280), mload(add(transcript, 0x61e0)))
            mstore(add(transcript, 0x62a0), mload(add(transcript, 0x6200)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6240),
                        0x80,
                        add(transcript, 0x6240),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x62c0), mload(add(transcript, 0xd40)))
            mstore(add(transcript, 0x62e0), mload(add(transcript, 0xd60)))
            mstore(add(transcript, 0x6300), mload(add(transcript, 0x4cc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x62c0),
                        0x60,
                        add(transcript, 0x62c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6320), mload(add(transcript, 0x6240)))
            mstore(add(transcript, 0x6340), mload(add(transcript, 0x6260)))
            mstore(add(transcript, 0x6360), mload(add(transcript, 0x62c0)))
            mstore(add(transcript, 0x6380), mload(add(transcript, 0x62e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6320),
                        0x80,
                        add(transcript, 0x6320),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x63a0), mload(add(transcript, 0x6320)))
            mstore(add(transcript, 0x63c0), mload(add(transcript, 0x6340)))
            mstore(add(transcript, 0x63e0), mload(add(transcript, 0xd40)))
            mstore(add(transcript, 0x6400), mload(add(transcript, 0xd60)))
            mstore(add(transcript, 0x6420), mload(add(transcript, 0xd80)))
            mstore(add(transcript, 0x6440), mload(add(transcript, 0xda0)))
            mstore(add(transcript, 0x6460), mload(add(transcript, 0xdc0)))
            mstore(add(transcript, 0x6480), mload(add(transcript, 0xde0)))
            mstore(
                add(transcript, 0x64a0),
                keccak256(add(transcript, 0x63a0), 256)
            )
            mstore(add(transcript, 0x64c0), mod(mload(25760), f_q))
            mstore(
                add(transcript, 0x64e0),
                mulmod(
                    mload(add(transcript, 0x64c0)),
                    mload(add(transcript, 0x64c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x6500),
                mulmod(1, mload(add(transcript, 0x64c0)), f_q)
            )
            mstore(add(transcript, 0x6520), mload(add(transcript, 0x6420)))
            mstore(add(transcript, 0x6540), mload(add(transcript, 0x6440)))
            mstore(add(transcript, 0x6560), mload(add(transcript, 0x6500)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6520),
                        0x60,
                        add(transcript, 0x6520),
                        0x40
                    ),
                    1
                ),
                success
            )
            // mstore(add(transcript, 0x6580), mload(add(transcript, 0x63a0)))
            // mstore(add(transcript, 0x65a0), mload(add(transcript, 0x63c0)))
            // mstore(add(transcript, 0x65c0), mload(add(transcript, 0x6520)))
            // mstore(add(transcript, 0x65e0), mload(add(transcript, 0x6540)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6580),
                        0x80,
                        add(transcript, 0x6580),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6600), mload(add(transcript, 0x6460)))
            mstore(add(transcript, 0x6620), mload(add(transcript, 0x6480)))
            mstore(add(transcript, 0x6640), mload(add(transcript, 0x6500)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6600),
                        0x60,
                        add(transcript, 0x6600),
                        0x40
                    ),
                    1
                ),
                success
            )
            // mstore(add(transcript, 0x6660), mload(add(transcript, 0x63e0)))
            // mstore(add(transcript, 0x6680), mload(add(transcript, 0x6400)))
            // mstore(add(transcript, 0x66a0), mload(add(transcript, 0x6600)))
            // mstore(add(transcript, 0x66c0), mload(add(transcript, 0x6620)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6660),
                        0x80,
                        add(transcript, 0x6660),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x66e0), mload(add(transcript, 0x6580)))
            mstore(add(transcript, 0x6700), mload(add(transcript, 0x65a0)))
            mstore(
                add(transcript, 0x6720),
                0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
            )
            mstore(
                add(transcript, 0x6740),
                0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
            )
            mstore(
                add(transcript, 0x6760),
                0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
            )
            mstore(
                add(transcript, 0x6780),
                0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
            )
            mstore(add(transcript, 0x67a0), mload(add(transcript, 0x6660)))
            mstore(add(transcript, 0x67c0), mload(add(transcript, 0x6680)))
            mstore(
                add(transcript, 0x67e0),
                0x1cf8832646b03608390dd9a6f7c6de581e065a2c99be3cd7e2259c0738c19051
            )
            mstore(
                add(transcript, 0x6800),
                0x068db4b87c697bd9906371fc2e24e522e20ca527952bfe058b3225974acf545f
            )
            mstore(
                add(transcript, 0x6820),
                0x01fdf661dc9860278308a39ac4e8214b55996acd015119a41baf7dc2ecbcd71b
            )
            mstore(
                add(transcript, 0x6840),
                0x2f69939a4701e1090159fcd62d8804f026626380dc72d6f2fa9ea681671c8800
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x8,
                        add(transcript, 0x66e0),
                        0x180,
                        add(transcript, 0x66e0),
                        0x20
                    ),
                    1
                ),
                success
            )
            success := and(eq(mload(add(transcript, 0x66e0)), 1), success)
        }
        return success;
    }
}
