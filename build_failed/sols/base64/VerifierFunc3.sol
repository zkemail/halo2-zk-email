// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "../VerifierFuncAbst.sol";

contract VerifierFunc3 is VerifierFuncAbst {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes memory _transcript
    ) public view override returns (bool, bytes memory) {
        bytes32[2049] memory transcript;
        // require(_transcript.length == 2049, "transcript length is not 2049");
        if (_transcript.length != 0) {
            transcript = abi.decode(_transcript, (bytes32[2049]));
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
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xdb40),
                            0x80,
                            add(transcript, 0xdb40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xdbc0),
                    0x0000000000000000000000000000000000000000000000000000000000000000
                )
                mstore(
                    add(transcript, 0xdbe0),
                    0x0000000000000000000000000000000000000000000000000000000000000000
                )
                mstore(add(transcript, 0xdc00), mload(add(transcript, 0xa7e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xdbc0),
                            0x60,
                            add(transcript, 0xdbc0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xdc20), mload(add(transcript, 0xdb40)))
                mstore(add(transcript, 0xdc40), mload(add(transcript, 0xdb60)))
                mstore(add(transcript, 0xdc60), mload(add(transcript, 0xdbc0)))
                mstore(add(transcript, 0xdc80), mload(add(transcript, 0xdbe0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xdc20),
                            0x80,
                            add(transcript, 0xdc20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xdca0),
                    0x2faca51be3307d055994fe42562217d07a0841b3d5b6acaac8993a1967eea84a
                )
                mstore(
                    add(transcript, 0xdcc0),
                    0x17c82c45208cce88b36a65f193006642d813839d9671ada458340c45834f37bc
                )
                mstore(add(transcript, 0xdce0), mload(add(transcript, 0xa800)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xdca0),
                            0x60,
                            add(transcript, 0xdca0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xdd00), mload(add(transcript, 0xdc20)))
                mstore(add(transcript, 0xdd20), mload(add(transcript, 0xdc40)))
                mstore(add(transcript, 0xdd40), mload(add(transcript, 0xdca0)))
                mstore(add(transcript, 0xdd60), mload(add(transcript, 0xdcc0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xdd00),
                            0x80,
                            add(transcript, 0xdd00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xdd80),
                    0x2b6c1cb22d15c8fc77c3c2be72a72981efde121e6d291043c09f0e713973e21f
                )
                mstore(
                    add(transcript, 0xdda0),
                    0x036ccb36d0bee9285b06c6a8cae7b3b2b6e7561dd962f0f2f851947bcd15a18b
                )
                mstore(add(transcript, 0xddc0), mload(add(transcript, 0xa820)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xdd80),
                            0x60,
                            add(transcript, 0xdd80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xdde0), mload(add(transcript, 0xdd00)))
                mstore(add(transcript, 0xde00), mload(add(transcript, 0xdd20)))
                mstore(add(transcript, 0xde20), mload(add(transcript, 0xdd80)))
                mstore(add(transcript, 0xde40), mload(add(transcript, 0xdda0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xdde0),
                            0x80,
                            add(transcript, 0xdde0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xde60),
                    0x061980de76eafa6406c4626b7bdbbf5e994b2b0af2a72a1fb345c027b346fd16
                )
                mstore(
                    add(transcript, 0xde80),
                    0x043bcb9c4dd0440b849de3ac10d6d6008a4e4dd2090baec9ba521fd23b69323c
                )
                mstore(add(transcript, 0xdea0), mload(add(transcript, 0xa840)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xde60),
                            0x60,
                            add(transcript, 0xde60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xdec0), mload(add(transcript, 0xdde0)))
                mstore(add(transcript, 0xdee0), mload(add(transcript, 0xde00)))
                mstore(add(transcript, 0xdf00), mload(add(transcript, 0xde60)))
                mstore(add(transcript, 0xdf20), mload(add(transcript, 0xde80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xdec0),
                            0x80,
                            add(transcript, 0xdec0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xdf40),
                    0x127284723027fd4cb5623bc561214be5ab62caacdb5e4ab10bac10b5f5d29e43
                )
                mstore(
                    add(transcript, 0xdf60),
                    0x17901387b9477f48f34877f83f66d865b5a491c6fb13917120ed2501474551b9
                )
                mstore(add(transcript, 0xdf80), mload(add(transcript, 0xa860)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xdf40),
                            0x60,
                            add(transcript, 0xdf40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xdfa0), mload(add(transcript, 0xdec0)))
                mstore(add(transcript, 0xdfc0), mload(add(transcript, 0xdee0)))
                mstore(add(transcript, 0xdfe0), mload(add(transcript, 0xdf40)))
                mstore(add(transcript, 0xe000), mload(add(transcript, 0xdf60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xdfa0),
                            0x80,
                            add(transcript, 0xdfa0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xe020),
                    0x2ad78ba7dcef705e2fa8ff604e79549c513e14a4bd4a3915c92c8563e0b42c18
                )
                mstore(
                    add(transcript, 0xe040),
                    0x1ec7e83d57a33dedae7941885c076985226ce3784147d2676eae8c8ef0b7c871
                )
                mstore(add(transcript, 0xe060), mload(add(transcript, 0xa880)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe020),
                            0x60,
                            add(transcript, 0xe020),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe080), mload(add(transcript, 0xdfa0)))
                mstore(add(transcript, 0xe0a0), mload(add(transcript, 0xdfc0)))
                mstore(add(transcript, 0xe0c0), mload(add(transcript, 0xe020)))
                mstore(add(transcript, 0xe0e0), mload(add(transcript, 0xe040)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xe080),
                            0x80,
                            add(transcript, 0xe080),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xe100),
                    0x115375c4589b6922ad9de276f551894adfb7815609d21b0ee5771d74eab3c3d7
                )
                mstore(
                    add(transcript, 0xe120),
                    0x27ebffe5633b945283153af352cec4d071ce33eebfb736f726046a74202aa72a
                )
                mstore(add(transcript, 0xe140), mload(add(transcript, 0xa8a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe100),
                            0x60,
                            add(transcript, 0xe100),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe160), mload(add(transcript, 0xe080)))
                mstore(add(transcript, 0xe180), mload(add(transcript, 0xe0a0)))
                mstore(add(transcript, 0xe1a0), mload(add(transcript, 0xe100)))
                mstore(add(transcript, 0xe1c0), mload(add(transcript, 0xe120)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xe160),
                            0x80,
                            add(transcript, 0xe160),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xe1e0),
                    0x101ce953d97b16794d7f4554d2840ab6119f63bcf5aab04db70802ec73d5d0b1
                )
                mstore(
                    add(transcript, 0xe200),
                    0x175cda852110c69273449da6099fcd97e800d130a1524ee4a88db65d213e1bd9
                )
                mstore(add(transcript, 0xe220), mload(add(transcript, 0xa8c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe1e0),
                            0x60,
                            add(transcript, 0xe1e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe240), mload(add(transcript, 0xe160)))
                mstore(add(transcript, 0xe260), mload(add(transcript, 0xe180)))
                mstore(add(transcript, 0xe280), mload(add(transcript, 0xe1e0)))
                mstore(add(transcript, 0xe2a0), mload(add(transcript, 0xe200)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xe240),
                            0x80,
                            add(transcript, 0xe240),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xe2c0),
                    0x2e4ddb019ee1a7bfbc2119424fea14649487c7b712d919af9987dd7adbfb1ef0
                )
                mstore(
                    add(transcript, 0xe2e0),
                    0x12c866b881f22478b9b8d238a9e4ae6ac11a4e48df8089e2a350977d68f93862
                )
                mstore(add(transcript, 0xe300), mload(add(transcript, 0xa8e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe2c0),
                            0x60,
                            add(transcript, 0xe2c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe320), mload(add(transcript, 0xe240)))
                mstore(add(transcript, 0xe340), mload(add(transcript, 0xe260)))
                mstore(add(transcript, 0xe360), mload(add(transcript, 0xe2c0)))
                mstore(add(transcript, 0xe380), mload(add(transcript, 0xe2e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xe320),
                            0x80,
                            add(transcript, 0xe320),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xe3a0),
                    0x1b6dea5d6694f3f846e346df344d8820c4976a99881ac57740ade77ef4a75dc6
                )
                mstore(
                    add(transcript, 0xe3c0),
                    0x020c3cf2e4977bcce01d822c5f7c65b5e2f7ca839ac43ca4b5f180b7179bff0f
                )
                mstore(add(transcript, 0xe3e0), mload(add(transcript, 0xa900)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe3a0),
                            0x60,
                            add(transcript, 0xe3a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe400), mload(add(transcript, 0xe320)))
                mstore(add(transcript, 0xe420), mload(add(transcript, 0xe340)))
                mstore(add(transcript, 0xe440), mload(add(transcript, 0xe3a0)))
                mstore(add(transcript, 0xe460), mload(add(transcript, 0xe3c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xe400),
                            0x80,
                            add(transcript, 0xe400),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xe480),
                    0x1d91327ab63f08a1b0c33f0fe437a4922a9bf86cb9b76570dcc6e83e7c07fb75
                )
                mstore(
                    add(transcript, 0xe4a0),
                    0x1b10ca94b93273bf2bae135c083bbc5ab38372cd7f8f88803e596779b43c3610
                )
                mstore(add(transcript, 0xe4c0), mload(add(transcript, 0xa920)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe480),
                            0x60,
                            add(transcript, 0xe480),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe4e0), mload(add(transcript, 0xe400)))
                mstore(add(transcript, 0xe500), mload(add(transcript, 0xe420)))
                mstore(add(transcript, 0xe520), mload(add(transcript, 0xe480)))
                mstore(add(transcript, 0xe540), mload(add(transcript, 0xe4a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xe4e0),
                            0x80,
                            add(transcript, 0xe4e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xe560),
                    0x11830f11abb01cf1391aadd8384dcd9dad58ae05979a9569c7e079332bb146aa
                )
                mstore(
                    add(transcript, 0xe580),
                    0x16d7f7a638a1716098cf73fa286d521d910852c7e85f6b7879ac2fa847327d2d
                )
                mstore(add(transcript, 0xe5a0), mload(add(transcript, 0xa940)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe560),
                            0x60,
                            add(transcript, 0xe560),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe5c0), mload(add(transcript, 0xe4e0)))
                mstore(add(transcript, 0xe5e0), mload(add(transcript, 0xe500)))
                mstore(add(transcript, 0xe600), mload(add(transcript, 0xe560)))
                mstore(add(transcript, 0xe620), mload(add(transcript, 0xe580)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xe5c0),
                            0x80,
                            add(transcript, 0xe5c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xe640),
                    0x1ce324b4891f84128174b7a8edbca6175306322137f5549e3c55a64eb1d43a34
                )
                mstore(
                    add(transcript, 0xe660),
                    0x0c09a8180a2d679cc10e80f384f7b51687fcb7fbe4d61fae88b3daff6b811bb6
                )
                mstore(add(transcript, 0xe680), mload(add(transcript, 0xa960)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe640),
                            0x60,
                            add(transcript, 0xe640),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe6a0), mload(add(transcript, 0xe5c0)))
                mstore(add(transcript, 0xe6c0), mload(add(transcript, 0xe5e0)))
                mstore(add(transcript, 0xe6e0), mload(add(transcript, 0xe640)))
                mstore(add(transcript, 0xe700), mload(add(transcript, 0xe660)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xe6a0),
                            0x80,
                            add(transcript, 0xe6a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xe720),
                    0x283c3145ac4cda6cf932494e424f858d92202d03167cfb499bbccf2459a81bc7
                )
                mstore(
                    add(transcript, 0xe740),
                    0x291ef27641c5ae1a6d037b9c30fec2d2458df0ffacb77f463d20c808991756ba
                )
                mstore(add(transcript, 0xe760), mload(add(transcript, 0xa980)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe720),
                            0x60,
                            add(transcript, 0xe720),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe780), mload(add(transcript, 0xe6a0)))
                mstore(add(transcript, 0xe7a0), mload(add(transcript, 0xe6c0)))
                mstore(add(transcript, 0xe7c0), mload(add(transcript, 0xe720)))
                mstore(add(transcript, 0xe7e0), mload(add(transcript, 0xe740)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xe780),
                            0x80,
                            add(transcript, 0xe780),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe800), mload(add(transcript, 0xe60)))
                mstore(add(transcript, 0xe820), mload(add(transcript, 0xe80)))
                mstore(add(transcript, 0xe840), mload(add(transcript, 0xa9a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe800),
                            0x60,
                            add(transcript, 0xe800),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe860), mload(add(transcript, 0xe780)))
                mstore(add(transcript, 0xe880), mload(add(transcript, 0xe7a0)))
                mstore(add(transcript, 0xe8a0), mload(add(transcript, 0xe800)))
                mstore(add(transcript, 0xe8c0), mload(add(transcript, 0xe820)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xe860),
                            0x80,
                            add(transcript, 0xe860),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe8e0), mload(add(transcript, 0xea0)))
                mstore(add(transcript, 0xe900), mload(add(transcript, 0xec0)))
                mstore(add(transcript, 0xe920), mload(add(transcript, 0xa9c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe8e0),
                            0x60,
                            add(transcript, 0xe8e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe940), mload(add(transcript, 0xe860)))
                mstore(add(transcript, 0xe960), mload(add(transcript, 0xe880)))
                mstore(add(transcript, 0xe980), mload(add(transcript, 0xe8e0)))
                mstore(add(transcript, 0xe9a0), mload(add(transcript, 0xe900)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xe940),
                            0x80,
                            add(transcript, 0xe940),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xe9c0), mload(add(transcript, 0xee0)))
                mstore(add(transcript, 0xe9e0), mload(add(transcript, 0xf00)))
                mstore(add(transcript, 0xea00), mload(add(transcript, 0xa9e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xe9c0),
                            0x60,
                            add(transcript, 0xe9c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xea20), mload(add(transcript, 0xe940)))
                mstore(add(transcript, 0xea40), mload(add(transcript, 0xe960)))
                mstore(add(transcript, 0xea60), mload(add(transcript, 0xe9c0)))
                mstore(add(transcript, 0xea80), mload(add(transcript, 0xe9e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xea20),
                            0x80,
                            add(transcript, 0xea20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xeaa0), mload(add(transcript, 0xf20)))
                mstore(add(transcript, 0xeac0), mload(add(transcript, 0xf40)))
                mstore(add(transcript, 0xeae0), mload(add(transcript, 0xaa00)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xeaa0),
                            0x60,
                            add(transcript, 0xeaa0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xeb00), mload(add(transcript, 0xea20)))
                mstore(add(transcript, 0xeb20), mload(add(transcript, 0xea40)))
                mstore(add(transcript, 0xeb40), mload(add(transcript, 0xeaa0)))
                mstore(add(transcript, 0xeb60), mload(add(transcript, 0xeac0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xeb00),
                            0x80,
                            add(transcript, 0xeb00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xeb80), mload(add(transcript, 0xdc0)))
                mstore(add(transcript, 0xeba0), mload(add(transcript, 0xde0)))
                mstore(add(transcript, 0xebc0), mload(add(transcript, 0xaa20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xeb80),
                            0x60,
                            add(transcript, 0xeb80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xebe0), mload(add(transcript, 0xeb00)))
                mstore(add(transcript, 0xec00), mload(add(transcript, 0xeb20)))
                mstore(add(transcript, 0xec20), mload(add(transcript, 0xeb80)))
                mstore(add(transcript, 0xec40), mload(add(transcript, 0xeba0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xebe0),
                            0x80,
                            add(transcript, 0xebe0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xec60), mload(add(transcript, 0xac0)))
                mstore(add(transcript, 0xec80), mload(add(transcript, 0xae0)))
                mstore(add(transcript, 0xeca0), mload(add(transcript, 0xad00)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xec60),
                            0x60,
                            add(transcript, 0xec60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xecc0), mload(add(transcript, 0xebe0)))
                mstore(add(transcript, 0xece0), mload(add(transcript, 0xec00)))
                mstore(add(transcript, 0xed00), mload(add(transcript, 0xec60)))
                mstore(add(transcript, 0xed20), mload(add(transcript, 0xec80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xecc0),
                            0x80,
                            add(transcript, 0xecc0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xed40), mload(add(transcript, 0xb00)))
                mstore(add(transcript, 0xed60), mload(add(transcript, 0xb20)))
                mstore(add(transcript, 0xed80), mload(add(transcript, 0xad20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xed40),
                            0x60,
                            add(transcript, 0xed40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xeda0), mload(add(transcript, 0xecc0)))
                mstore(add(transcript, 0xedc0), mload(add(transcript, 0xece0)))
                mstore(add(transcript, 0xede0), mload(add(transcript, 0xed40)))
                mstore(add(transcript, 0xee00), mload(add(transcript, 0xed60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xeda0),
                            0x80,
                            add(transcript, 0xeda0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xee20), mload(add(transcript, 0xb40)))
                mstore(add(transcript, 0xee40), mload(add(transcript, 0xb60)))
                mstore(add(transcript, 0xee60), mload(add(transcript, 0xad40)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xee20),
                            0x60,
                            add(transcript, 0xee20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xee80), mload(add(transcript, 0xeda0)))
                mstore(add(transcript, 0xeea0), mload(add(transcript, 0xedc0)))
                mstore(add(transcript, 0xeec0), mload(add(transcript, 0xee20)))
                mstore(add(transcript, 0xeee0), mload(add(transcript, 0xee40)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xee80),
                            0x80,
                            add(transcript, 0xee80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xef00), mload(add(transcript, 0xb80)))
                mstore(add(transcript, 0xef20), mload(add(transcript, 0xba0)))
                mstore(add(transcript, 0xef40), mload(add(transcript, 0xad60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xef00),
                            0x60,
                            add(transcript, 0xef00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xef60), mload(add(transcript, 0xee80)))
                mstore(add(transcript, 0xef80), mload(add(transcript, 0xeea0)))
                mstore(add(transcript, 0xefa0), mload(add(transcript, 0xef00)))
                mstore(add(transcript, 0xefc0), mload(add(transcript, 0xef20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xef60),
                            0x80,
                            add(transcript, 0xef60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xefe0), mload(add(transcript, 0xbc0)))
                mstore(add(transcript, 0xf000), mload(add(transcript, 0xbe0)))
                mstore(add(transcript, 0xf020), mload(add(transcript, 0xb2c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xefe0),
                            0x60,
                            add(transcript, 0xefe0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf040), mload(add(transcript, 0xef60)))
                mstore(add(transcript, 0xf060), mload(add(transcript, 0xef80)))
                mstore(add(transcript, 0xf080), mload(add(transcript, 0xefe0)))
                mstore(add(transcript, 0xf0a0), mload(add(transcript, 0xf000)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf040),
                            0x80,
                            add(transcript, 0xf040),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf0c0), mload(add(transcript, 0xc00)))
                mstore(add(transcript, 0xf0e0), mload(add(transcript, 0xc20)))
                mstore(add(transcript, 0xf100), mload(add(transcript, 0xb2e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xf0c0),
                            0x60,
                            add(transcript, 0xf0c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf120), mload(add(transcript, 0xf040)))
                mstore(add(transcript, 0xf140), mload(add(transcript, 0xf060)))
                mstore(add(transcript, 0xf160), mload(add(transcript, 0xf0c0)))
                mstore(add(transcript, 0xf180), mload(add(transcript, 0xf0e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf120),
                            0x80,
                            add(transcript, 0xf120),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf1a0), mload(add(transcript, 0xc40)))
                mstore(add(transcript, 0xf1c0), mload(add(transcript, 0xc60)))
                mstore(add(transcript, 0xf1e0), mload(add(transcript, 0xb300)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xf1a0),
                            0x60,
                            add(transcript, 0xf1a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf200), mload(add(transcript, 0xf120)))
                mstore(add(transcript, 0xf220), mload(add(transcript, 0xf140)))
                mstore(add(transcript, 0xf240), mload(add(transcript, 0xf1a0)))
                mstore(add(transcript, 0xf260), mload(add(transcript, 0xf1c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf200),
                            0x80,
                            add(transcript, 0xf200),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf280), mload(add(transcript, 0xc80)))
                mstore(add(transcript, 0xf2a0), mload(add(transcript, 0xca0)))
                mstore(add(transcript, 0xf2c0), mload(add(transcript, 0xb320)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xf280),
                            0x60,
                            add(transcript, 0xf280),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf2e0), mload(add(transcript, 0xf200)))
                mstore(add(transcript, 0xf300), mload(add(transcript, 0xf220)))
                mstore(add(transcript, 0xf320), mload(add(transcript, 0xf280)))
                mstore(add(transcript, 0xf340), mload(add(transcript, 0xf2a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf2e0),
                            0x80,
                            add(transcript, 0xf2e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf360), mload(add(transcript, 0xcc0)))
                mstore(add(transcript, 0xf380), mload(add(transcript, 0xce0)))
                mstore(add(transcript, 0xf3a0), mload(add(transcript, 0xb340)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xf360),
                            0x60,
                            add(transcript, 0xf360),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf3c0), mload(add(transcript, 0xf2e0)))
                mstore(add(transcript, 0xf3e0), mload(add(transcript, 0xf300)))
                mstore(add(transcript, 0xf400), mload(add(transcript, 0xf360)))
                mstore(add(transcript, 0xf420), mload(add(transcript, 0xf380)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf3c0),
                            0x80,
                            add(transcript, 0xf3c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf440), mload(add(transcript, 0xd00)))
                mstore(add(transcript, 0xf460), mload(add(transcript, 0xd20)))
                mstore(add(transcript, 0xf480), mload(add(transcript, 0xb360)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xf440),
                            0x60,
                            add(transcript, 0xf440),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf4a0), mload(add(transcript, 0xf3c0)))
                mstore(add(transcript, 0xf4c0), mload(add(transcript, 0xf3e0)))
                mstore(add(transcript, 0xf4e0), mload(add(transcript, 0xf440)))
                mstore(add(transcript, 0xf500), mload(add(transcript, 0xf460)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf4a0),
                            0x80,
                            add(transcript, 0xf4a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf520), mload(add(transcript, 0xd40)))
                mstore(add(transcript, 0xf540), mload(add(transcript, 0xd60)))
                mstore(add(transcript, 0xf560), mload(add(transcript, 0xb380)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xf520),
                            0x60,
                            add(transcript, 0xf520),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf580), mload(add(transcript, 0xf4a0)))
                mstore(add(transcript, 0xf5a0), mload(add(transcript, 0xf4c0)))
                mstore(add(transcript, 0xf5c0), mload(add(transcript, 0xf520)))
                mstore(add(transcript, 0xf5e0), mload(add(transcript, 0xf540)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf580),
                            0x80,
                            add(transcript, 0xf580),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf600), mload(add(transcript, 0xd80)))
                mstore(add(transcript, 0xf620), mload(add(transcript, 0xda0)))
                mstore(add(transcript, 0xf640), mload(add(transcript, 0xb3a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xf600),
                            0x60,
                            add(transcript, 0xf600),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf660), mload(add(transcript, 0xf580)))
                mstore(add(transcript, 0xf680), mload(add(transcript, 0xf5a0)))
                mstore(add(transcript, 0xf6a0), mload(add(transcript, 0xf600)))
                mstore(add(transcript, 0xf6c0), mload(add(transcript, 0xf620)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf660),
                            0x80,
                            add(transcript, 0xf660),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf6e0), mload(add(transcript, 0x680)))
                mstore(add(transcript, 0xf700), mload(add(transcript, 0x6a0)))
                mstore(add(transcript, 0xf720), mload(add(transcript, 0xb860)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xf6e0),
                            0x60,
                            add(transcript, 0xf6e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf740), mload(add(transcript, 0xf660)))
                mstore(add(transcript, 0xf760), mload(add(transcript, 0xf680)))
                mstore(add(transcript, 0xf780), mload(add(transcript, 0xf6e0)))
                mstore(add(transcript, 0xf7a0), mload(add(transcript, 0xf700)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf740),
                            0x80,
                            add(transcript, 0xf740),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf7c0), mload(add(transcript, 0x700)))
                mstore(add(transcript, 0xf7e0), mload(add(transcript, 0x720)))
                mstore(add(transcript, 0xf800), mload(add(transcript, 0xb880)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xf7c0),
                            0x60,
                            add(transcript, 0xf7c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf820), mload(add(transcript, 0xf740)))
                mstore(add(transcript, 0xf840), mload(add(transcript, 0xf760)))
                mstore(add(transcript, 0xf860), mload(add(transcript, 0xf7c0)))
                mstore(add(transcript, 0xf880), mload(add(transcript, 0xf7e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf820),
                            0x80,
                            add(transcript, 0xf820),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf8a0), mload(add(transcript, 0x780)))
                mstore(add(transcript, 0xf8c0), mload(add(transcript, 0x7a0)))
                mstore(add(transcript, 0xf8e0), mload(add(transcript, 0xb8a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xf8a0),
                            0x60,
                            add(transcript, 0xf8a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf900), mload(add(transcript, 0xf820)))
                mstore(add(transcript, 0xf920), mload(add(transcript, 0xf840)))
                mstore(add(transcript, 0xf940), mload(add(transcript, 0xf8a0)))
                mstore(add(transcript, 0xf960), mload(add(transcript, 0xf8c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf900),
                            0x80,
                            add(transcript, 0xf900),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf980), mload(add(transcript, 0x800)))
                mstore(add(transcript, 0xf9a0), mload(add(transcript, 0x820)))
                mstore(add(transcript, 0xf9c0), mload(add(transcript, 0xb8c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xf980),
                            0x60,
                            add(transcript, 0xf980),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xf9e0), mload(add(transcript, 0xf900)))
                mstore(add(transcript, 0xfa00), mload(add(transcript, 0xf920)))
                mstore(add(transcript, 0xfa20), mload(add(transcript, 0xf980)))
                mstore(add(transcript, 0xfa40), mload(add(transcript, 0xf9a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xf9e0),
                            0x80,
                            add(transcript, 0xf9e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xfa60), mload(add(transcript, 0x880)))
                mstore(add(transcript, 0xfa80), mload(add(transcript, 0x8a0)))
                mstore(add(transcript, 0xfaa0), mload(add(transcript, 0xb8e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xfa60),
                            0x60,
                            add(transcript, 0xfa60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xfac0), mload(add(transcript, 0xf9e0)))
                mstore(add(transcript, 0xfae0), mload(add(transcript, 0xfa00)))
                mstore(add(transcript, 0xfb00), mload(add(transcript, 0xfa60)))
                mstore(add(transcript, 0xfb20), mload(add(transcript, 0xfa80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xfac0),
                            0x80,
                            add(transcript, 0xfac0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xfb40), mload(add(transcript, 0x900)))
                mstore(add(transcript, 0xfb60), mload(add(transcript, 0x920)))
                mstore(add(transcript, 0xfb80), mload(add(transcript, 0xb900)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xfb40),
                            0x60,
                            add(transcript, 0xfb40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xfba0), mload(add(transcript, 0xfac0)))
                mstore(add(transcript, 0xfbc0), mload(add(transcript, 0xfae0)))
                mstore(add(transcript, 0xfbe0), mload(add(transcript, 0xfb40)))
                mstore(add(transcript, 0xfc00), mload(add(transcript, 0xfb60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xfba0),
                            0x80,
                            add(transcript, 0xfba0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xfc20), mload(add(transcript, 0x980)))
                mstore(add(transcript, 0xfc40), mload(add(transcript, 0x9a0)))
                mstore(add(transcript, 0xfc60), mload(add(transcript, 0xb920)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xfc20),
                            0x60,
                            add(transcript, 0xfc20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xfc80), mload(add(transcript, 0xfba0)))
                mstore(add(transcript, 0xfca0), mload(add(transcript, 0xfbc0)))
                mstore(add(transcript, 0xfcc0), mload(add(transcript, 0xfc20)))
                mstore(add(transcript, 0xfce0), mload(add(transcript, 0xfc40)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xfc80),
                            0x80,
                            add(transcript, 0xfc80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xfd00), mload(add(transcript, 0x2040)))
                mstore(add(transcript, 0xfd20), mload(add(transcript, 0x2060)))
                mstore(
                    add(transcript, 0xfd40),
                    sub(f_q, mload(add(transcript, 0xb960)))
                )
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xfd00),
                            0x60,
                            add(transcript, 0xfd00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xfd60), mload(add(transcript, 0xfc80)))
                mstore(add(transcript, 0xfd80), mload(add(transcript, 0xfca0)))
                mstore(add(transcript, 0xfda0), mload(add(transcript, 0xfd00)))
                mstore(add(transcript, 0xfdc0), mload(add(transcript, 0xfd20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xfd60),
                            0x80,
                            add(transcript, 0xfd60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xfde0), mload(add(transcript, 0x20e0)))
                mstore(add(transcript, 0xfe00), mload(add(transcript, 0x2100)))
                mstore(add(transcript, 0xfe20), mload(add(transcript, 0xb980)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xfde0),
                            0x60,
                            add(transcript, 0xfde0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xfe40), mload(add(transcript, 0xfd60)))
                mstore(add(transcript, 0xfe60), mload(add(transcript, 0xfd80)))
                mstore(add(transcript, 0xfe80), mload(add(transcript, 0xfde0)))
                mstore(add(transcript, 0xfea0), mload(add(transcript, 0xfe00)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xfe40),
                            0x80,
                            add(transcript, 0xfe40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xfec0), mload(add(transcript, 0xfe40)))
                mstore(add(transcript, 0xfee0), mload(add(transcript, 0xfe60)))
                mstore(
                    add(transcript, 0xff00),
                    0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
                )
                mstore(
                    add(transcript, 0xff20),
                    0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
                )
                mstore(
                    add(transcript, 0xff40),
                    0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
                )
                mstore(
                    add(transcript, 0xff60),
                    0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
                )
                mstore(add(transcript, 0xff80), mload(add(transcript, 0x20e0)))
                mstore(add(transcript, 0xffa0), mload(add(transcript, 0x2100)))
                mstore(
                    add(transcript, 0xffc0),
                    0x02bb08cd02255f03f68752a49670aff168f06c4dc3e61da06dc4c01f0fdcd224
                )
                mstore(
                    add(transcript, 0xffe0),
                    0x172011b5a9f869c9c43b284680eec21bca494674b484f92bd4deba7511c686ce
                )
                mstore(
                    add(transcript, 0x10000),
                    0x1b3856aa8ebe922476cec5710d73672c1bff1476980854b2978d07a9f8eaca72
                )
                mstore(
                    add(transcript, 0x10020),
                    0x24c10b4979af6e3215b78d5d2ac15148b7030f658117741046443d6acbcdef0c
                )
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x8,
                            add(transcript, 0xfec0),
                            0x180,
                            add(transcript, 0xfec0),
                            0x20
                        ),
                        1
                    ),
                    success
                )
                success := and(eq(mload(add(transcript, 0xfec0)), 1), success)
            }
        }
        bytes memory transcriptBytes = abi.encode(transcript);
        // bytes32[] memory newTranscript = new bytes32[](2049);
        // for(uint i=0; i<_transcript.length; i++) {
        //     newTranscript[i] = transcript[i];
        // }
        // require(newTranscript.length == 2049, "newTranscript length is not 2049");
        return (success, transcriptBytes);
    }
}
