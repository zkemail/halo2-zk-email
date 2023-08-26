// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "../VerifierFuncAbst.sol";

contract VerifierFunc2 is VerifierFuncAbst {
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
                mstore(add(transcript, 0x8f40), mload(add(transcript, 0x6d80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8f00),
                            0x60,
                            add(transcript, 0x8f00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8f60), mload(add(transcript, 0x8e80)))
                mstore(add(transcript, 0x8f80), mload(add(transcript, 0x8ea0)))
                mstore(add(transcript, 0x8fa0), mload(add(transcript, 0x8f00)))
                mstore(add(transcript, 0x8fc0), mload(add(transcript, 0x8f20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8f60),
                            0x80,
                            add(transcript, 0x8f60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8fe0),
                    0x2e4ddb019ee1a7bfbc2119424fea14649487c7b712d919af9987dd7adbfb1ef0
                )
                mstore(
                    add(transcript, 0x9000),
                    0x12c866b881f22478b9b8d238a9e4ae6ac11a4e48df8089e2a350977d68f93862
                )
                mstore(add(transcript, 0x9020), mload(add(transcript, 0x6da0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8fe0),
                            0x60,
                            add(transcript, 0x8fe0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9040), mload(add(transcript, 0x8f60)))
                mstore(add(transcript, 0x9060), mload(add(transcript, 0x8f80)))
                mstore(add(transcript, 0x9080), mload(add(transcript, 0x8fe0)))
                mstore(add(transcript, 0x90a0), mload(add(transcript, 0x9000)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9040),
                            0x80,
                            add(transcript, 0x9040),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x90c0),
                    0x1b6dea5d6694f3f846e346df344d8820c4976a99881ac57740ade77ef4a75dc6
                )
                mstore(
                    add(transcript, 0x90e0),
                    0x020c3cf2e4977bcce01d822c5f7c65b5e2f7ca839ac43ca4b5f180b7179bff0f
                )
                mstore(add(transcript, 0x9100), mload(add(transcript, 0x6dc0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x90c0),
                            0x60,
                            add(transcript, 0x90c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9120), mload(add(transcript, 0x9040)))
                mstore(add(transcript, 0x9140), mload(add(transcript, 0x9060)))
                mstore(add(transcript, 0x9160), mload(add(transcript, 0x90c0)))
                mstore(add(transcript, 0x9180), mload(add(transcript, 0x90e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9120),
                            0x80,
                            add(transcript, 0x9120),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x91a0),
                    0x2c5d15922bdb93946b39643c6b8405fe722f5bfd73d1099e7f93083febcb8443
                )
                mstore(
                    add(transcript, 0x91c0),
                    0x155e2fad8d794d53d11147314ddb16353e99e1acfff445c5252742cf4b904a5c
                )
                mstore(add(transcript, 0x91e0), mload(add(transcript, 0x6de0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x91a0),
                            0x60,
                            add(transcript, 0x91a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9200), mload(add(transcript, 0x9120)))
                mstore(add(transcript, 0x9220), mload(add(transcript, 0x9140)))
                mstore(add(transcript, 0x9240), mload(add(transcript, 0x91a0)))
                mstore(add(transcript, 0x9260), mload(add(transcript, 0x91c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9200),
                            0x80,
                            add(transcript, 0x9200),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x9280),
                    0x12ebae3dbde5062921effe1f39baa26d2dee39ff71d29ff5124af68bb00bb491
                )
                mstore(
                    add(transcript, 0x92a0),
                    0x19cb9ad8b63739627e7d7457fb7d30dd2bbb5fc3474864989743701caccb2259
                )
                mstore(add(transcript, 0x92c0), mload(add(transcript, 0x6e00)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9280),
                            0x60,
                            add(transcript, 0x9280),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x92e0), mload(add(transcript, 0x9200)))
                mstore(add(transcript, 0x9300), mload(add(transcript, 0x9220)))
                mstore(add(transcript, 0x9320), mload(add(transcript, 0x9280)))
                mstore(add(transcript, 0x9340), mload(add(transcript, 0x92a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x92e0),
                            0x80,
                            add(transcript, 0x92e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x9360),
                    0x266aa114af4f62718e45eea084aa0cfd46ceb66d3ec058c276e2aa216dafb44f
                )
                mstore(
                    add(transcript, 0x9380),
                    0x09a83464ea8e5a5db8f2cdc310d95180b2f8f04cfc73042472c420b19a797bb8
                )
                mstore(add(transcript, 0x93a0), mload(add(transcript, 0x6e20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9360),
                            0x60,
                            add(transcript, 0x9360),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x93c0), mload(add(transcript, 0x92e0)))
                mstore(add(transcript, 0x93e0), mload(add(transcript, 0x9300)))
                mstore(add(transcript, 0x9400), mload(add(transcript, 0x9360)))
                mstore(add(transcript, 0x9420), mload(add(transcript, 0x9380)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x93c0),
                            0x80,
                            add(transcript, 0x93c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x9440),
                    0x1fe30832554af8abae3f3575df34ceed5d90f99ccbc5b6038a344c7b3706d664
                )
                mstore(
                    add(transcript, 0x9460),
                    0x08d8232fe7c188379338132a014472d152a3b7363d375ebbb949c0ec444d5547
                )
                mstore(add(transcript, 0x9480), mload(add(transcript, 0x6e40)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9440),
                            0x60,
                            add(transcript, 0x9440),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x94a0), mload(add(transcript, 0x93c0)))
                mstore(add(transcript, 0x94c0), mload(add(transcript, 0x93e0)))
                mstore(add(transcript, 0x94e0), mload(add(transcript, 0x9440)))
                mstore(add(transcript, 0x9500), mload(add(transcript, 0x9460)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x94a0),
                            0x80,
                            add(transcript, 0x94a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9520), mload(add(transcript, 0x840)))
                mstore(add(transcript, 0x9540), mload(add(transcript, 0x860)))
                mstore(add(transcript, 0x9560), mload(add(transcript, 0x6e60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9520),
                            0x60,
                            add(transcript, 0x9520),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9580), mload(add(transcript, 0x94a0)))
                mstore(add(transcript, 0x95a0), mload(add(transcript, 0x94c0)))
                mstore(add(transcript, 0x95c0), mload(add(transcript, 0x9520)))
                mstore(add(transcript, 0x95e0), mload(add(transcript, 0x9540)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9580),
                            0x80,
                            add(transcript, 0x9580),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9600), mload(add(transcript, 0x880)))
                mstore(add(transcript, 0x9620), mload(add(transcript, 0x8a0)))
                mstore(add(transcript, 0x9640), mload(add(transcript, 0x6e80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9600),
                            0x60,
                            add(transcript, 0x9600),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9660), mload(add(transcript, 0x9580)))
                mstore(add(transcript, 0x9680), mload(add(transcript, 0x95a0)))
                mstore(add(transcript, 0x96a0), mload(add(transcript, 0x9600)))
                mstore(add(transcript, 0x96c0), mload(add(transcript, 0x9620)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9660),
                            0x80,
                            add(transcript, 0x9660),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x96e0), mload(add(transcript, 0x8c0)))
                mstore(add(transcript, 0x9700), mload(add(transcript, 0x8e0)))
                mstore(add(transcript, 0x9720), mload(add(transcript, 0x6ea0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x96e0),
                            0x60,
                            add(transcript, 0x96e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9740), mload(add(transcript, 0x9660)))
                mstore(add(transcript, 0x9760), mload(add(transcript, 0x9680)))
                mstore(add(transcript, 0x9780), mload(add(transcript, 0x96e0)))
                mstore(add(transcript, 0x97a0), mload(add(transcript, 0x9700)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9740),
                            0x80,
                            add(transcript, 0x9740),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x97c0), mload(add(transcript, 0x7a0)))
                mstore(add(transcript, 0x97e0), mload(add(transcript, 0x7c0)))
                mstore(add(transcript, 0x9800), mload(add(transcript, 0x6ec0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x97c0),
                            0x60,
                            add(transcript, 0x97c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9820), mload(add(transcript, 0x9740)))
                mstore(add(transcript, 0x9840), mload(add(transcript, 0x9760)))
                mstore(add(transcript, 0x9860), mload(add(transcript, 0x97c0)))
                mstore(add(transcript, 0x9880), mload(add(transcript, 0x97e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9820),
                            0x80,
                            add(transcript, 0x9820),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x98a0), mload(add(transcript, 0x560)))
                mstore(add(transcript, 0x98c0), mload(add(transcript, 0x580)))
                mstore(add(transcript, 0x98e0), mload(add(transcript, 0x72e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x98a0),
                            0x60,
                            add(transcript, 0x98a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9900), mload(add(transcript, 0x9820)))
                mstore(add(transcript, 0x9920), mload(add(transcript, 0x9840)))
                mstore(add(transcript, 0x9940), mload(add(transcript, 0x98a0)))
                mstore(add(transcript, 0x9960), mload(add(transcript, 0x98c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9900),
                            0x80,
                            add(transcript, 0x9900),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9980), mload(add(transcript, 0x5a0)))
                mstore(add(transcript, 0x99a0), mload(add(transcript, 0x5c0)))
                mstore(add(transcript, 0x99c0), mload(add(transcript, 0x7300)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9980),
                            0x60,
                            add(transcript, 0x9980),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x99e0), mload(add(transcript, 0x9900)))
                mstore(add(transcript, 0x9a00), mload(add(transcript, 0x9920)))
                mstore(add(transcript, 0x9a20), mload(add(transcript, 0x9980)))
                mstore(add(transcript, 0x9a40), mload(add(transcript, 0x99a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x99e0),
                            0x80,
                            add(transcript, 0x99e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9a60), mload(add(transcript, 0x5e0)))
                mstore(add(transcript, 0x9a80), mload(add(transcript, 0x600)))
                mstore(add(transcript, 0x9aa0), mload(add(transcript, 0x7320)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9a60),
                            0x60,
                            add(transcript, 0x9a60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9ac0), mload(add(transcript, 0x99e0)))
                mstore(add(transcript, 0x9ae0), mload(add(transcript, 0x9a00)))
                mstore(add(transcript, 0x9b00), mload(add(transcript, 0x9a60)))
                mstore(add(transcript, 0x9b20), mload(add(transcript, 0x9a80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9ac0),
                            0x80,
                            add(transcript, 0x9ac0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9b40), mload(add(transcript, 0x620)))
                mstore(add(transcript, 0x9b60), mload(add(transcript, 0x640)))
                mstore(add(transcript, 0x9b80), mload(add(transcript, 0x7340)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9b40),
                            0x60,
                            add(transcript, 0x9b40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9ba0), mload(add(transcript, 0x9ac0)))
                mstore(add(transcript, 0x9bc0), mload(add(transcript, 0x9ae0)))
                mstore(add(transcript, 0x9be0), mload(add(transcript, 0x9b40)))
                mstore(add(transcript, 0x9c00), mload(add(transcript, 0x9b60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9ba0),
                            0x80,
                            add(transcript, 0x9ba0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9c20), mload(add(transcript, 0x660)))
                mstore(add(transcript, 0x9c40), mload(add(transcript, 0x680)))
                mstore(add(transcript, 0x9c60), mload(add(transcript, 0x7360)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9c20),
                            0x60,
                            add(transcript, 0x9c20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9c80), mload(add(transcript, 0x9ba0)))
                mstore(add(transcript, 0x9ca0), mload(add(transcript, 0x9bc0)))
                mstore(add(transcript, 0x9cc0), mload(add(transcript, 0x9c20)))
                mstore(add(transcript, 0x9ce0), mload(add(transcript, 0x9c40)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9c80),
                            0x80,
                            add(transcript, 0x9c80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9d00), mload(add(transcript, 0x6a0)))
                mstore(add(transcript, 0x9d20), mload(add(transcript, 0x6c0)))
                mstore(add(transcript, 0x9d40), mload(add(transcript, 0x7380)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9d00),
                            0x60,
                            add(transcript, 0x9d00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9d60), mload(add(transcript, 0x9c80)))
                mstore(add(transcript, 0x9d80), mload(add(transcript, 0x9ca0)))
                mstore(add(transcript, 0x9da0), mload(add(transcript, 0x9d00)))
                mstore(add(transcript, 0x9dc0), mload(add(transcript, 0x9d20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9d60),
                            0x80,
                            add(transcript, 0x9d60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9de0), mload(add(transcript, 0x6e0)))
                mstore(add(transcript, 0x9e00), mload(add(transcript, 0x700)))
                mstore(add(transcript, 0x9e20), mload(add(transcript, 0x75c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9de0),
                            0x60,
                            add(transcript, 0x9de0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9e40), mload(add(transcript, 0x9d60)))
                mstore(add(transcript, 0x9e60), mload(add(transcript, 0x9d80)))
                mstore(add(transcript, 0x9e80), mload(add(transcript, 0x9de0)))
                mstore(add(transcript, 0x9ea0), mload(add(transcript, 0x9e00)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9e40),
                            0x80,
                            add(transcript, 0x9e40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9ec0), mload(add(transcript, 0x720)))
                mstore(add(transcript, 0x9ee0), mload(add(transcript, 0x740)))
                mstore(add(transcript, 0x9f00), mload(add(transcript, 0x75e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9ec0),
                            0x60,
                            add(transcript, 0x9ec0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9f20), mload(add(transcript, 0x9e40)))
                mstore(add(transcript, 0x9f40), mload(add(transcript, 0x9e60)))
                mstore(add(transcript, 0x9f60), mload(add(transcript, 0x9ec0)))
                mstore(add(transcript, 0x9f80), mload(add(transcript, 0x9ee0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x9f20),
                            0x80,
                            add(transcript, 0x9f20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x9fa0), mload(add(transcript, 0x760)))
                mstore(add(transcript, 0x9fc0), mload(add(transcript, 0x780)))
                mstore(add(transcript, 0x9fe0), mload(add(transcript, 0x7600)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x9fa0),
                            0x60,
                            add(transcript, 0x9fa0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xa000), mload(add(transcript, 0x9f20)))
                mstore(add(transcript, 0xa020), mload(add(transcript, 0x9f40)))
                mstore(add(transcript, 0xa040), mload(add(transcript, 0x9fa0)))
                mstore(add(transcript, 0xa060), mload(add(transcript, 0x9fc0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xa000),
                            0x80,
                            add(transcript, 0xa000),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xa080), mload(add(transcript, 0x3a0)))
                mstore(add(transcript, 0xa0a0), mload(add(transcript, 0x3c0)))
                mstore(add(transcript, 0xa0c0), mload(add(transcript, 0x77a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xa080),
                            0x60,
                            add(transcript, 0xa080),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xa0e0), mload(add(transcript, 0xa000)))
                mstore(add(transcript, 0xa100), mload(add(transcript, 0xa020)))
                mstore(add(transcript, 0xa120), mload(add(transcript, 0xa080)))
                mstore(add(transcript, 0xa140), mload(add(transcript, 0xa0a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xa0e0),
                            0x80,
                            add(transcript, 0xa0e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xa160), mload(add(transcript, 0x420)))
                mstore(add(transcript, 0xa180), mload(add(transcript, 0x440)))
                mstore(add(transcript, 0xa1a0), mload(add(transcript, 0x77c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xa160),
                            0x60,
                            add(transcript, 0xa160),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xa1c0), mload(add(transcript, 0xa0e0)))
                mstore(add(transcript, 0xa1e0), mload(add(transcript, 0xa100)))
                mstore(add(transcript, 0xa200), mload(add(transcript, 0xa160)))
                mstore(add(transcript, 0xa220), mload(add(transcript, 0xa180)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xa1c0),
                            0x80,
                            add(transcript, 0xa1c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xa240), mload(add(transcript, 0x1500)))
                mstore(add(transcript, 0xa260), mload(add(transcript, 0x1520)))
                mstore(
                    add(transcript, 0xa280),
                    sub(f_q, mload(add(transcript, 0x7800)))
                )
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xa240),
                            0x60,
                            add(transcript, 0xa240),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xa2a0), mload(add(transcript, 0xa1c0)))
                mstore(add(transcript, 0xa2c0), mload(add(transcript, 0xa1e0)))
                mstore(add(transcript, 0xa2e0), mload(add(transcript, 0xa240)))
                mstore(add(transcript, 0xa300), mload(add(transcript, 0xa260)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xa2a0),
                            0x80,
                            add(transcript, 0xa2a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xa320), mload(add(transcript, 0x15a0)))
                mstore(add(transcript, 0xa340), mload(add(transcript, 0x15c0)))
                mstore(add(transcript, 0xa360), mload(add(transcript, 0x7820)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xa320),
                            0x60,
                            add(transcript, 0xa320),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xa380), mload(add(transcript, 0xa2a0)))
                mstore(add(transcript, 0xa3a0), mload(add(transcript, 0xa2c0)))
                mstore(add(transcript, 0xa3c0), mload(add(transcript, 0xa320)))
                mstore(add(transcript, 0xa3e0), mload(add(transcript, 0xa340)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xa380),
                            0x80,
                            add(transcript, 0xa380),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xa400), mload(add(transcript, 0xa380)))
                mstore(add(transcript, 0xa420), mload(add(transcript, 0xa3a0)))
                mstore(
                    add(transcript, 0xa440),
                    0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
                )
                mstore(
                    add(transcript, 0xa460),
                    0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
                )
                mstore(
                    add(transcript, 0xa480),
                    0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
                )
                mstore(
                    add(transcript, 0xa4a0),
                    0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
                )
                mstore(add(transcript, 0xa4c0), mload(add(transcript, 0x15a0)))
                mstore(add(transcript, 0xa4e0), mload(add(transcript, 0x15c0)))
                mstore(
                    add(transcript, 0xa500),
                    0x02bb08cd02255f03f68752a49670aff168f06c4dc3e61da06dc4c01f0fdcd224
                )
                mstore(
                    add(transcript, 0xa520),
                    0x172011b5a9f869c9c43b284680eec21bca494674b484f92bd4deba7511c686ce
                )
                mstore(
                    add(transcript, 0xa540),
                    0x1b3856aa8ebe922476cec5710d73672c1bff1476980854b2978d07a9f8eaca72
                )
                mstore(
                    add(transcript, 0xa560),
                    0x24c10b4979af6e3215b78d5d2ac15148b7030f658117741046443d6acbcdef0c
                )
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x8,
                            add(transcript, 0xa400),
                            0x180,
                            add(transcript, 0xa400),
                            0x20
                        ),
                        1
                    ),
                    success
                )
                success := and(eq(mload(add(transcript, 0xa400)), 1), success)
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
