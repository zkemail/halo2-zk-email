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
                mstore(
                    add(transcript, 0x90a0),
                    mulmod(
                        mload(add(transcript, 0x9080)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x90c0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x90a0))),
                        mload(add(transcript, 0x7a80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x90e0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7a80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9100),
                    addmod(
                        mload(add(transcript, 0x9060)),
                        mload(add(transcript, 0x90c0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1e20)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9120), result)
                }
                mstore(
                    add(transcript, 0x9140),
                    mulmod(
                        mload(add(transcript, 0x9120)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9160),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9140))),
                        mload(add(transcript, 0x7aa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9180),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7aa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x91a0),
                    addmod(
                        mload(add(transcript, 0x9100)),
                        mload(add(transcript, 0x9160)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1ec0)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x91c0), result)
                }
                mstore(
                    add(transcript, 0x91e0),
                    mulmod(
                        mload(add(transcript, 0x91c0)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9200),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x91e0))),
                        mload(add(transcript, 0x7ac0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9220),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7ac0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9240),
                    addmod(
                        mload(add(transcript, 0x91a0)),
                        mload(add(transcript, 0x9200)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1f60)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9260), result)
                }
                mstore(
                    add(transcript, 0x9280),
                    mulmod(
                        mload(add(transcript, 0x9260)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x92a0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9280))),
                        mload(add(transcript, 0x7ae0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x92c0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7ae0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x92e0),
                    addmod(
                        mload(add(transcript, 0x9240)),
                        mload(add(transcript, 0x92a0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1640)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9300), result)
                }
                mstore(
                    add(transcript, 0x9320),
                    mulmod(
                        mload(add(transcript, 0x9300)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9340),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9320))),
                        mload(add(transcript, 0x7b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9360),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7b00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9380),
                    addmod(
                        mload(add(transcript, 0x92e0)),
                        mload(add(transcript, 0x9340)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1660)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x93a0), result)
                }
                mstore(
                    add(transcript, 0x93c0),
                    mulmod(
                        mload(add(transcript, 0x93a0)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x93e0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x93c0))),
                        mload(add(transcript, 0x7b20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9400),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7b20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9420),
                    addmod(
                        mload(add(transcript, 0x9380)),
                        mload(add(transcript, 0x93e0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1680)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9440), result)
                }
                mstore(
                    add(transcript, 0x9460),
                    mulmod(
                        mload(add(transcript, 0x9440)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9480),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9460))),
                        mload(add(transcript, 0x7b40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x94a0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7b40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x94c0),
                    addmod(
                        mload(add(transcript, 0x9420)),
                        mload(add(transcript, 0x9480)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x16a0)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x94e0), result)
                }
                mstore(
                    add(transcript, 0x9500),
                    mulmod(
                        mload(add(transcript, 0x94e0)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9520),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9500))),
                        mload(add(transcript, 0x7b60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9540),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7b60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9560),
                    addmod(
                        mload(add(transcript, 0x94c0)),
                        mload(add(transcript, 0x9520)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x16c0)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9580), result)
                }
                mstore(
                    add(transcript, 0x95a0),
                    mulmod(
                        mload(add(transcript, 0x9580)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x95c0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x95a0))),
                        mload(add(transcript, 0x7b80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x95e0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7b80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9600),
                    addmod(
                        mload(add(transcript, 0x9560)),
                        mload(add(transcript, 0x95c0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x16e0)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9620), result)
                }
                mstore(
                    add(transcript, 0x9640),
                    mulmod(
                        mload(add(transcript, 0x9620)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9660),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9640))),
                        mload(add(transcript, 0x7ba0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9680),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7ba0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x96a0),
                    addmod(
                        mload(add(transcript, 0x9600)),
                        mload(add(transcript, 0x9660)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1700)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x96c0), result)
                }
                mstore(
                    add(transcript, 0x96e0),
                    mulmod(
                        mload(add(transcript, 0x96c0)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9700),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x96e0))),
                        mload(add(transcript, 0x7bc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9720),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7bc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9740),
                    addmod(
                        mload(add(transcript, 0x96a0)),
                        mload(add(transcript, 0x9700)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1720)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9760), result)
                }
                mstore(
                    add(transcript, 0x9780),
                    mulmod(
                        mload(add(transcript, 0x9760)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x97a0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9780))),
                        mload(add(transcript, 0x7be0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x97c0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7be0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x97e0),
                    addmod(
                        mload(add(transcript, 0x9740)),
                        mload(add(transcript, 0x97a0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1740)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9800), result)
                }
                mstore(
                    add(transcript, 0x9820),
                    mulmod(
                        mload(add(transcript, 0x9800)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9840),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9820))),
                        mload(add(transcript, 0x7c00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9860),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7c00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9880),
                    addmod(
                        mload(add(transcript, 0x97e0)),
                        mload(add(transcript, 0x9840)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1760)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x98a0), result)
                }
                mstore(
                    add(transcript, 0x98c0),
                    mulmod(
                        mload(add(transcript, 0x98a0)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x98e0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x98c0))),
                        mload(add(transcript, 0x7c20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9900),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7c20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9920),
                    addmod(
                        mload(add(transcript, 0x9880)),
                        mload(add(transcript, 0x98e0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1780)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9940), result)
                }
                mstore(
                    add(transcript, 0x9960),
                    mulmod(
                        mload(add(transcript, 0x9940)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9980),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9960))),
                        mload(add(transcript, 0x7c40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x99a0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7c40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x99c0),
                    addmod(
                        mload(add(transcript, 0x9920)),
                        mload(add(transcript, 0x9980)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x99e0),
                    addmod(
                        mload(add(transcript, 0x9900)),
                        mload(add(transcript, 0x99a0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x17c0)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9a00), result)
                }
                mstore(
                    add(transcript, 0x9a20),
                    mulmod(
                        mload(add(transcript, 0x9a00)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9a40),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9a20))),
                        mload(add(transcript, 0x7c60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9a60),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7c60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9a80),
                    addmod(
                        mload(add(transcript, 0x99c0)),
                        mload(add(transcript, 0x9a40)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x17e0)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9aa0), result)
                }
                mstore(
                    add(transcript, 0x9ac0),
                    mulmod(
                        mload(add(transcript, 0x9aa0)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9ae0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9ac0))),
                        mload(add(transcript, 0x7c80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9b00),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7c80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9b20),
                    addmod(
                        mload(add(transcript, 0x9a80)),
                        mload(add(transcript, 0x9ae0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1800)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9b40), result)
                }
                mstore(
                    add(transcript, 0x9b60),
                    mulmod(
                        mload(add(transcript, 0x9b40)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9b80),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9b60))),
                        mload(add(transcript, 0x7ca0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9ba0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7ca0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9bc0),
                    addmod(
                        mload(add(transcript, 0x9b20)),
                        mload(add(transcript, 0x9b80)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1820)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9be0), result)
                }
                mstore(
                    add(transcript, 0x9c00),
                    mulmod(
                        mload(add(transcript, 0x9be0)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9c20),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9c00))),
                        mload(add(transcript, 0x7cc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9c40),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7cc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9c60),
                    addmod(
                        mload(add(transcript, 0x9bc0)),
                        mload(add(transcript, 0x9c20)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1840)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9c80), result)
                }
                mstore(
                    add(transcript, 0x9ca0),
                    mulmod(
                        mload(add(transcript, 0x9c80)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9cc0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9ca0))),
                        mload(add(transcript, 0x7ce0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9ce0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7ce0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9d00),
                    addmod(
                        mload(add(transcript, 0x9c60)),
                        mload(add(transcript, 0x9cc0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1860)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9d20), result)
                }
                mstore(
                    add(transcript, 0x9d40),
                    mulmod(
                        mload(add(transcript, 0x9d20)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9d60),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9d40))),
                        mload(add(transcript, 0x7d00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9d80),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7d00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9da0),
                    addmod(
                        mload(add(transcript, 0x9d00)),
                        mload(add(transcript, 0x9d60)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1880)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9dc0), result)
                }
                mstore(
                    add(transcript, 0x9de0),
                    mulmod(
                        mload(add(transcript, 0x9dc0)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9e00),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9de0))),
                        mload(add(transcript, 0x7d20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9e20),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7d20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9e40),
                    addmod(
                        mload(add(transcript, 0x9da0)),
                        mload(add(transcript, 0x9e00)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x18a0)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9e60), result)
                }
                mstore(
                    add(transcript, 0x9e80),
                    mulmod(
                        mload(add(transcript, 0x9e60)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9ea0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9e80))),
                        mload(add(transcript, 0x7d40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9ec0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7d40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9ee0),
                    addmod(
                        mload(add(transcript, 0x9e40)),
                        mload(add(transcript, 0x9ea0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x18c0)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9f00), result)
                }
                mstore(
                    add(transcript, 0x9f20),
                    mulmod(
                        mload(add(transcript, 0x9f00)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9f40),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9f20))),
                        mload(add(transcript, 0x7d60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9f60),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7d60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9f80),
                    addmod(
                        mload(add(transcript, 0x9ee0)),
                        mload(add(transcript, 0x9f40)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x18e0)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0x9fa0), result)
                }
                mstore(
                    add(transcript, 0x9fc0),
                    mulmod(
                        mload(add(transcript, 0x9fa0)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x9fe0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x9fc0))),
                        mload(add(transcript, 0x7d80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa000),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7d80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa020),
                    addmod(
                        mload(add(transcript, 0x9f80)),
                        mload(add(transcript, 0x9fe0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1900)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0xa040), result)
                }
                mstore(
                    add(transcript, 0xa060),
                    mulmod(
                        mload(add(transcript, 0xa040)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa080),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xa060))),
                        mload(add(transcript, 0x7da0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa0a0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7da0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa0c0),
                    addmod(
                        mload(add(transcript, 0xa020)),
                        mload(add(transcript, 0xa080)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1920)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0xa0e0), result)
                }
                mstore(
                    add(transcript, 0xa100),
                    mulmod(
                        mload(add(transcript, 0xa0e0)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa120),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xa100))),
                        mload(add(transcript, 0x7dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa140),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7dc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa160),
                    addmod(
                        mload(add(transcript, 0xa0c0)),
                        mload(add(transcript, 0xa120)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1940)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0xa180), result)
                }
                mstore(
                    add(transcript, 0xa1a0),
                    mulmod(
                        mload(add(transcript, 0xa180)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa1c0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xa1a0))),
                        mload(add(transcript, 0x7de0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa1e0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7de0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa200),
                    addmod(
                        mload(add(transcript, 0xa160)),
                        mload(add(transcript, 0xa1c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa220),
                    mulmod(
                        mload(add(transcript, 0x6d40)),
                        mload(add(transcript, 0x75a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa240),
                    mulmod(
                        mload(add(transcript, 0x6d60)),
                        mload(add(transcript, 0x75a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa260),
                    mulmod(
                        mload(add(transcript, 0x6d80)),
                        mload(add(transcript, 0x75a0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x6da0)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0xa280), result)
                }
                mstore(
                    add(transcript, 0xa2a0),
                    mulmod(
                        mload(add(transcript, 0xa280)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa2c0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xa2a0))),
                        mload(add(transcript, 0x7e00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa2e0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7e00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa300),
                    mulmod(
                        mload(add(transcript, 0xa220)),
                        mload(add(transcript, 0x7e00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa320),
                    mulmod(
                        mload(add(transcript, 0xa240)),
                        mload(add(transcript, 0x7e00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa340),
                    mulmod(
                        mload(add(transcript, 0xa260)),
                        mload(add(transcript, 0x7e00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa360),
                    addmod(
                        mload(add(transcript, 0xa200)),
                        mload(add(transcript, 0xa2c0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x17a0)),
                        mload(add(transcript, 0x70c0)),
                        f_q
                    )
                    mstore(add(transcript, 0xa380), result)
                }
                mstore(
                    add(transcript, 0xa3a0),
                    mulmod(
                        mload(add(transcript, 0xa380)),
                        mload(add(transcript, 0x7840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa3c0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xa3a0))),
                        mload(add(transcript, 0x7e20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa3e0),
                    mulmod(
                        mload(add(transcript, 0x8680)),
                        mload(add(transcript, 0x7e20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa400),
                    addmod(
                        mload(add(transcript, 0xa360)),
                        mload(add(transcript, 0xa3c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa420),
                    mulmod(
                        mload(add(transcript, 0xa400)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa440),
                    mulmod(
                        mload(add(transcript, 0x8700)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa460),
                    mulmod(
                        mload(add(transcript, 0x8780)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa480),
                    mulmod(
                        mload(add(transcript, 0x8820)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa4a0),
                    mulmod(
                        mload(add(transcript, 0x88c0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa4c0),
                    mulmod(
                        mload(add(transcript, 0x8960)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa4e0),
                    mulmod(
                        mload(add(transcript, 0x8a00)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa500),
                    mulmod(
                        mload(add(transcript, 0x8aa0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa520),
                    mulmod(
                        mload(add(transcript, 0x8b40)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa540),
                    mulmod(
                        mload(add(transcript, 0x8be0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa560),
                    mulmod(
                        mload(add(transcript, 0x8c80)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa580),
                    mulmod(
                        mload(add(transcript, 0x8d20)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa5a0),
                    mulmod(
                        mload(add(transcript, 0x8dc0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa5c0),
                    mulmod(
                        mload(add(transcript, 0x8e60)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa5e0),
                    mulmod(
                        mload(add(transcript, 0x8f00)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa600),
                    mulmod(
                        mload(add(transcript, 0x8fa0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa620),
                    mulmod(
                        mload(add(transcript, 0x9040)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa640),
                    mulmod(
                        mload(add(transcript, 0x90e0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa660),
                    mulmod(
                        mload(add(transcript, 0x9180)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa680),
                    mulmod(
                        mload(add(transcript, 0x9220)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa6a0),
                    mulmod(
                        mload(add(transcript, 0x92c0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa6c0),
                    mulmod(
                        mload(add(transcript, 0x9360)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa6e0),
                    mulmod(
                        mload(add(transcript, 0x9400)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa700),
                    mulmod(
                        mload(add(transcript, 0x94a0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa720),
                    mulmod(
                        mload(add(transcript, 0x9540)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa740),
                    mulmod(
                        mload(add(transcript, 0x95e0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa760),
                    mulmod(
                        mload(add(transcript, 0x9680)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa780),
                    mulmod(
                        mload(add(transcript, 0x9720)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa7a0),
                    mulmod(
                        mload(add(transcript, 0x97c0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa7c0),
                    mulmod(
                        mload(add(transcript, 0x9860)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa7e0),
                    mulmod(
                        mload(add(transcript, 0x99e0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa800),
                    mulmod(
                        mload(add(transcript, 0x9a60)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa820),
                    mulmod(
                        mload(add(transcript, 0x9b00)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa840),
                    mulmod(
                        mload(add(transcript, 0x9ba0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa860),
                    mulmod(
                        mload(add(transcript, 0x9c40)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa880),
                    mulmod(
                        mload(add(transcript, 0x9ce0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa8a0),
                    mulmod(
                        mload(add(transcript, 0x9d80)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa8c0),
                    mulmod(
                        mload(add(transcript, 0x9e20)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa8e0),
                    mulmod(
                        mload(add(transcript, 0x9ec0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa900),
                    mulmod(
                        mload(add(transcript, 0x9f60)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa920),
                    mulmod(
                        mload(add(transcript, 0xa000)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa940),
                    mulmod(
                        mload(add(transcript, 0xa0a0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa960),
                    mulmod(
                        mload(add(transcript, 0xa140)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa980),
                    mulmod(
                        mload(add(transcript, 0xa1e0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa9a0),
                    mulmod(
                        mload(add(transcript, 0xa2e0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa9c0),
                    mulmod(
                        mload(add(transcript, 0xa300)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xa9e0),
                    mulmod(
                        mload(add(transcript, 0xa320)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xaa00),
                    mulmod(
                        mload(add(transcript, 0xa340)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xaa20),
                    mulmod(
                        mload(add(transcript, 0xa3e0)),
                        mload(add(transcript, 0x7e60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xaa40),
                    addmod(
                        mload(add(transcript, 0x8660)),
                        mload(add(transcript, 0xa420)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xaa60),
                    mulmod(1, mload(add(transcript, 0x75e0)), f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1960)),
                        mload(add(transcript, 0x70e0)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1980)),
                            mload(add(transcript, 0x7100)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x19a0)),
                            mload(add(transcript, 0x7120)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xaa80), result)
                }
                mstore(
                    add(transcript, 0xaaa0),
                    mulmod(
                        mload(add(transcript, 0xaa80)),
                        mload(add(transcript, 0x7860)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xaac0),
                    mulmod(sub(f_q, mload(add(transcript, 0xaaa0))), 1, f_q)
                )
                mstore(
                    add(transcript, 0xaae0),
                    mulmod(mload(add(transcript, 0xaa60)), 1, f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x19c0)),
                        mload(add(transcript, 0x70e0)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x19e0)),
                            mload(add(transcript, 0x7100)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1a00)),
                            mload(add(transcript, 0x7120)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xab00), result)
                }
                mstore(
                    add(transcript, 0xab20),
                    mulmod(
                        mload(add(transcript, 0xab00)),
                        mload(add(transcript, 0x7860)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xab40),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xab20))),
                        mload(add(transcript, 0x1fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xab60),
                    mulmod(
                        mload(add(transcript, 0xaa60)),
                        mload(add(transcript, 0x1fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xab80),
                    addmod(
                        mload(add(transcript, 0xaac0)),
                        mload(add(transcript, 0xab40)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1a20)),
                        mload(add(transcript, 0x70e0)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1a40)),
                            mload(add(transcript, 0x7100)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1a60)),
                            mload(add(transcript, 0x7120)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xaba0), result)
                }
                mstore(
                    add(transcript, 0xabc0),
                    mulmod(
                        mload(add(transcript, 0xaba0)),
                        mload(add(transcript, 0x7860)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xabe0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xabc0))),
                        mload(add(transcript, 0x78c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xac00),
                    mulmod(
                        mload(add(transcript, 0xaa60)),
                        mload(add(transcript, 0x78c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xac20),
                    addmod(
                        mload(add(transcript, 0xab80)),
                        mload(add(transcript, 0xabe0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1a80)),
                        mload(add(transcript, 0x70e0)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1aa0)),
                            mload(add(transcript, 0x7100)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1ac0)),
                            mload(add(transcript, 0x7120)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xac40), result)
                }
                mstore(
                    add(transcript, 0xac60),
                    mulmod(
                        mload(add(transcript, 0xac40)),
                        mload(add(transcript, 0x7860)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xac80),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xac60))),
                        mload(add(transcript, 0x78e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xaca0),
                    mulmod(
                        mload(add(transcript, 0xaa60)),
                        mload(add(transcript, 0x78e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xacc0),
                    addmod(
                        mload(add(transcript, 0xac20)),
                        mload(add(transcript, 0xac80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xace0),
                    mulmod(
                        mload(add(transcript, 0xacc0)),
                        mload(add(transcript, 0x7e80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xad00),
                    mulmod(
                        mload(add(transcript, 0xaae0)),
                        mload(add(transcript, 0x7e80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xad20),
                    mulmod(
                        mload(add(transcript, 0xab60)),
                        mload(add(transcript, 0x7e80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xad40),
                    mulmod(
                        mload(add(transcript, 0xac00)),
                        mload(add(transcript, 0x7e80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xad60),
                    mulmod(
                        mload(add(transcript, 0xaca0)),
                        mload(add(transcript, 0x7e80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xad80),
                    addmod(
                        mload(add(transcript, 0xaa40)),
                        mload(add(transcript, 0xace0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xada0),
                    mulmod(1, mload(add(transcript, 0x7620)), f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1ae0)),
                        mload(add(transcript, 0x7160)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1b00)),
                            mload(add(transcript, 0x7180)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xadc0), result)
                }
                mstore(
                    add(transcript, 0xade0),
                    mulmod(
                        mload(add(transcript, 0xadc0)),
                        mload(add(transcript, 0x7880)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xae00),
                    mulmod(sub(f_q, mload(add(transcript, 0xade0))), 1, f_q)
                )
                mstore(
                    add(transcript, 0xae20),
                    mulmod(mload(add(transcript, 0xada0)), 1, f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1b20)),
                        mload(add(transcript, 0x7160)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1b40)),
                            mload(add(transcript, 0x7180)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xae40), result)
                }
                mstore(
                    add(transcript, 0xae60),
                    mulmod(
                        mload(add(transcript, 0xae40)),
                        mload(add(transcript, 0x7880)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xae80),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xae60))),
                        mload(add(transcript, 0x1fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xaea0),
                    mulmod(
                        mload(add(transcript, 0xada0)),
                        mload(add(transcript, 0x1fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xaec0),
                    addmod(
                        mload(add(transcript, 0xae00)),
                        mload(add(transcript, 0xae80)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1bc0)),
                        mload(add(transcript, 0x7160)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1be0)),
                            mload(add(transcript, 0x7180)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xaee0), result)
                }
                mstore(
                    add(transcript, 0xaf00),
                    mulmod(
                        mload(add(transcript, 0xaee0)),
                        mload(add(transcript, 0x7880)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xaf20),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xaf00))),
                        mload(add(transcript, 0x78c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xaf40),
                    mulmod(
                        mload(add(transcript, 0xada0)),
                        mload(add(transcript, 0x78c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xaf60),
                    addmod(
                        mload(add(transcript, 0xaec0)),
                        mload(add(transcript, 0xaf20)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1c60)),
                        mload(add(transcript, 0x7160)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1c80)),
                            mload(add(transcript, 0x7180)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xaf80), result)
                }
                mstore(
                    add(transcript, 0xafa0),
                    mulmod(
                        mload(add(transcript, 0xaf80)),
                        mload(add(transcript, 0x7880)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xafc0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xafa0))),
                        mload(add(transcript, 0x78e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xafe0),
                    mulmod(
                        mload(add(transcript, 0xada0)),
                        mload(add(transcript, 0x78e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb000),
                    addmod(
                        mload(add(transcript, 0xaf60)),
                        mload(add(transcript, 0xafc0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1d00)),
                        mload(add(transcript, 0x7160)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1d20)),
                            mload(add(transcript, 0x7180)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xb020), result)
                }
                mstore(
                    add(transcript, 0xb040),
                    mulmod(
                        mload(add(transcript, 0xb020)),
                        mload(add(transcript, 0x7880)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb060),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xb040))),
                        mload(add(transcript, 0x7900)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb080),
                    mulmod(
                        mload(add(transcript, 0xada0)),
                        mload(add(transcript, 0x7900)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb0a0),
                    addmod(
                        mload(add(transcript, 0xb000)),
                        mload(add(transcript, 0xb060)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1da0)),
                        mload(add(transcript, 0x7160)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1dc0)),
                            mload(add(transcript, 0x7180)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xb0c0), result)
                }
                mstore(
                    add(transcript, 0xb0e0),
                    mulmod(
                        mload(add(transcript, 0xb0c0)),
                        mload(add(transcript, 0x7880)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb100),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xb0e0))),
                        mload(add(transcript, 0x7920)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb120),
                    mulmod(
                        mload(add(transcript, 0xada0)),
                        mload(add(transcript, 0x7920)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb140),
                    addmod(
                        mload(add(transcript, 0xb0a0)),
                        mload(add(transcript, 0xb100)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1e40)),
                        mload(add(transcript, 0x7160)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1e60)),
                            mload(add(transcript, 0x7180)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xb160), result)
                }
                mstore(
                    add(transcript, 0xb180),
                    mulmod(
                        mload(add(transcript, 0xb160)),
                        mload(add(transcript, 0x7880)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb1a0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xb180))),
                        mload(add(transcript, 0x7940)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb1c0),
                    mulmod(
                        mload(add(transcript, 0xada0)),
                        mload(add(transcript, 0x7940)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb1e0),
                    addmod(
                        mload(add(transcript, 0xb140)),
                        mload(add(transcript, 0xb1a0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1ee0)),
                        mload(add(transcript, 0x7160)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1f00)),
                            mload(add(transcript, 0x7180)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xb200), result)
                }
                mstore(
                    add(transcript, 0xb220),
                    mulmod(
                        mload(add(transcript, 0xb200)),
                        mload(add(transcript, 0x7880)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb240),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xb220))),
                        mload(add(transcript, 0x7960)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb260),
                    mulmod(
                        mload(add(transcript, 0xada0)),
                        mload(add(transcript, 0x7960)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb280),
                    addmod(
                        mload(add(transcript, 0xb1e0)),
                        mload(add(transcript, 0xb240)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb2a0),
                    mulmod(
                        mload(add(transcript, 0xb280)),
                        mload(add(transcript, 0x7ea0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb2c0),
                    mulmod(
                        mload(add(transcript, 0xae20)),
                        mload(add(transcript, 0x7ea0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb2e0),
                    mulmod(
                        mload(add(transcript, 0xaea0)),
                        mload(add(transcript, 0x7ea0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb300),
                    mulmod(
                        mload(add(transcript, 0xaf40)),
                        mload(add(transcript, 0x7ea0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb320),
                    mulmod(
                        mload(add(transcript, 0xafe0)),
                        mload(add(transcript, 0x7ea0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb340),
                    mulmod(
                        mload(add(transcript, 0xb080)),
                        mload(add(transcript, 0x7ea0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb360),
                    mulmod(
                        mload(add(transcript, 0xb120)),
                        mload(add(transcript, 0x7ea0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb380),
                    mulmod(
                        mload(add(transcript, 0xb1c0)),
                        mload(add(transcript, 0x7ea0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb3a0),
                    mulmod(
                        mload(add(transcript, 0xb260)),
                        mload(add(transcript, 0x7ea0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb3c0),
                    addmod(
                        mload(add(transcript, 0xad80)),
                        mload(add(transcript, 0xb2a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb3e0),
                    mulmod(1, mload(add(transcript, 0x7660)), f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1b60)),
                        mload(add(transcript, 0x71a0)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1b80)),
                            mload(add(transcript, 0x71c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xb400), result)
                }
                mstore(
                    add(transcript, 0xb420),
                    mulmod(
                        mload(add(transcript, 0xb400)),
                        mload(add(transcript, 0x78a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb440),
                    mulmod(sub(f_q, mload(add(transcript, 0xb420))), 1, f_q)
                )
                mstore(
                    add(transcript, 0xb460),
                    mulmod(mload(add(transcript, 0xb3e0)), 1, f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1c00)),
                        mload(add(transcript, 0x71a0)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1c20)),
                            mload(add(transcript, 0x71c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xb480), result)
                }
                mstore(
                    add(transcript, 0xb4a0),
                    mulmod(
                        mload(add(transcript, 0xb480)),
                        mload(add(transcript, 0x78a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb4c0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xb4a0))),
                        mload(add(transcript, 0x1fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb4e0),
                    mulmod(
                        mload(add(transcript, 0xb3e0)),
                        mload(add(transcript, 0x1fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb500),
                    addmod(
                        mload(add(transcript, 0xb440)),
                        mload(add(transcript, 0xb4c0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1ca0)),
                        mload(add(transcript, 0x71a0)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1cc0)),
                            mload(add(transcript, 0x71c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xb520), result)
                }
                mstore(
                    add(transcript, 0xb540),
                    mulmod(
                        mload(add(transcript, 0xb520)),
                        mload(add(transcript, 0x78a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb560),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xb540))),
                        mload(add(transcript, 0x78c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb580),
                    mulmod(
                        mload(add(transcript, 0xb3e0)),
                        mload(add(transcript, 0x78c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb5a0),
                    addmod(
                        mload(add(transcript, 0xb500)),
                        mload(add(transcript, 0xb560)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1d40)),
                        mload(add(transcript, 0x71a0)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1d60)),
                            mload(add(transcript, 0x71c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xb5c0), result)
                }
                mstore(
                    add(transcript, 0xb5e0),
                    mulmod(
                        mload(add(transcript, 0xb5c0)),
                        mload(add(transcript, 0x78a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb600),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xb5e0))),
                        mload(add(transcript, 0x78e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb620),
                    mulmod(
                        mload(add(transcript, 0xb3e0)),
                        mload(add(transcript, 0x78e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb640),
                    addmod(
                        mload(add(transcript, 0xb5a0)),
                        mload(add(transcript, 0xb600)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1de0)),
                        mload(add(transcript, 0x71a0)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1e00)),
                            mload(add(transcript, 0x71c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xb660), result)
                }
                mstore(
                    add(transcript, 0xb680),
                    mulmod(
                        mload(add(transcript, 0xb660)),
                        mload(add(transcript, 0x78a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb6a0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xb680))),
                        mload(add(transcript, 0x7900)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb6c0),
                    mulmod(
                        mload(add(transcript, 0xb3e0)),
                        mload(add(transcript, 0x7900)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb6e0),
                    addmod(
                        mload(add(transcript, 0xb640)),
                        mload(add(transcript, 0xb6a0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1e80)),
                        mload(add(transcript, 0x71a0)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1ea0)),
                            mload(add(transcript, 0x71c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xb700), result)
                }
                mstore(
                    add(transcript, 0xb720),
                    mulmod(
                        mload(add(transcript, 0xb700)),
                        mload(add(transcript, 0x78a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb740),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xb720))),
                        mload(add(transcript, 0x7920)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb760),
                    mulmod(
                        mload(add(transcript, 0xb3e0)),
                        mload(add(transcript, 0x7920)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb780),
                    addmod(
                        mload(add(transcript, 0xb6e0)),
                        mload(add(transcript, 0xb740)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1f20)),
                        mload(add(transcript, 0x71a0)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1f40)),
                            mload(add(transcript, 0x71c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0xb7a0), result)
                }
                mstore(
                    add(transcript, 0xb7c0),
                    mulmod(
                        mload(add(transcript, 0xb7a0)),
                        mload(add(transcript, 0x78a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb7e0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0xb7c0))),
                        mload(add(transcript, 0x7940)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb800),
                    mulmod(
                        mload(add(transcript, 0xb3e0)),
                        mload(add(transcript, 0x7940)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb820),
                    addmod(
                        mload(add(transcript, 0xb780)),
                        mload(add(transcript, 0xb7e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb840),
                    mulmod(
                        mload(add(transcript, 0xb820)),
                        mload(add(transcript, 0x7ec0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb860),
                    mulmod(
                        mload(add(transcript, 0xb460)),
                        mload(add(transcript, 0x7ec0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb880),
                    mulmod(
                        mload(add(transcript, 0xb4e0)),
                        mload(add(transcript, 0x7ec0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb8a0),
                    mulmod(
                        mload(add(transcript, 0xb580)),
                        mload(add(transcript, 0x7ec0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb8c0),
                    mulmod(
                        mload(add(transcript, 0xb620)),
                        mload(add(transcript, 0x7ec0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb8e0),
                    mulmod(
                        mload(add(transcript, 0xb6c0)),
                        mload(add(transcript, 0x7ec0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb900),
                    mulmod(
                        mload(add(transcript, 0xb760)),
                        mload(add(transcript, 0x7ec0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb920),
                    mulmod(
                        mload(add(transcript, 0xb800)),
                        mload(add(transcript, 0x7ec0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb940),
                    addmod(
                        mload(add(transcript, 0xb3c0)),
                        mload(add(transcript, 0xb840)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0xb960),
                    mulmod(1, mload(add(transcript, 0x7040)), f_q)
                )
                mstore(
                    add(transcript, 0xb980),
                    mulmod(1, mload(add(transcript, 0x20a0)), f_q)
                )
                mstore(
                    add(transcript, 0xb9a0),
                    0x0000000000000000000000000000000000000000000000000000000000000001
                )
                mstore(
                    add(transcript, 0xb9c0),
                    0x0000000000000000000000000000000000000000000000000000000000000002
                )
                mstore(add(transcript, 0xb9e0), mload(add(transcript, 0xb940)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xb9a0),
                            0x60,
                            add(transcript, 0xb9a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xba00), mload(add(transcript, 0xb9a0)))
                mstore(add(transcript, 0xba20), mload(add(transcript, 0xb9c0)))
                mstore(add(transcript, 0xba40), mload(add(transcript, 0x60)))
                mstore(add(transcript, 0xba60), mload(add(transcript, 0x80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xba00),
                            0x80,
                            add(transcript, 0xba00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xba80), mload(add(transcript, 0xa0)))
                mstore(add(transcript, 0xbaa0), mload(add(transcript, 0xc0)))
                mstore(add(transcript, 0xbac0), mload(add(transcript, 0x8480)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xba80),
                            0x60,
                            add(transcript, 0xba80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbae0), mload(add(transcript, 0xba00)))
                mstore(add(transcript, 0xbb00), mload(add(transcript, 0xba20)))
                mstore(add(transcript, 0xbb20), mload(add(transcript, 0xba80)))
                mstore(add(transcript, 0xbb40), mload(add(transcript, 0xbaa0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xbae0),
                            0x80,
                            add(transcript, 0xbae0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbb60), mload(add(transcript, 0xe0)))
                mstore(add(transcript, 0xbb80), mload(add(transcript, 0x100)))
                mstore(add(transcript, 0xbba0), mload(add(transcript, 0x84a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xbb60),
                            0x60,
                            add(transcript, 0xbb60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbbc0), mload(add(transcript, 0xbae0)))
                mstore(add(transcript, 0xbbe0), mload(add(transcript, 0xbb00)))
                mstore(add(transcript, 0xbc00), mload(add(transcript, 0xbb60)))
                mstore(add(transcript, 0xbc20), mload(add(transcript, 0xbb80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xbbc0),
                            0x80,
                            add(transcript, 0xbbc0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbc40), mload(add(transcript, 0x120)))
                mstore(add(transcript, 0xbc60), mload(add(transcript, 0x140)))
                mstore(add(transcript, 0xbc80), mload(add(transcript, 0x84c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xbc40),
                            0x60,
                            add(transcript, 0xbc40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbca0), mload(add(transcript, 0xbbc0)))
                mstore(add(transcript, 0xbcc0), mload(add(transcript, 0xbbe0)))
                mstore(add(transcript, 0xbce0), mload(add(transcript, 0xbc40)))
                mstore(add(transcript, 0xbd00), mload(add(transcript, 0xbc60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xbca0),
                            0x80,
                            add(transcript, 0xbca0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbd20), mload(add(transcript, 0x160)))
                mstore(add(transcript, 0xbd40), mload(add(transcript, 0x180)))
                mstore(add(transcript, 0xbd60), mload(add(transcript, 0x84e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xbd20),
                            0x60,
                            add(transcript, 0xbd20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbd80), mload(add(transcript, 0xbca0)))
                mstore(add(transcript, 0xbda0), mload(add(transcript, 0xbcc0)))
                mstore(add(transcript, 0xbdc0), mload(add(transcript, 0xbd20)))
                mstore(add(transcript, 0xbde0), mload(add(transcript, 0xbd40)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xbd80),
                            0x80,
                            add(transcript, 0xbd80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbe00), mload(add(transcript, 0x1a0)))
                mstore(add(transcript, 0xbe20), mload(add(transcript, 0x1c0)))
                mstore(add(transcript, 0xbe40), mload(add(transcript, 0x8500)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xbe00),
                            0x60,
                            add(transcript, 0xbe00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbe60), mload(add(transcript, 0xbd80)))
                mstore(add(transcript, 0xbe80), mload(add(transcript, 0xbda0)))
                mstore(add(transcript, 0xbea0), mload(add(transcript, 0xbe00)))
                mstore(add(transcript, 0xbec0), mload(add(transcript, 0xbe20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xbe60),
                            0x80,
                            add(transcript, 0xbe60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbee0), mload(add(transcript, 0x1e0)))
                mstore(add(transcript, 0xbf00), mload(add(transcript, 0x200)))
                mstore(add(transcript, 0xbf20), mload(add(transcript, 0x8520)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xbee0),
                            0x60,
                            add(transcript, 0xbee0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbf40), mload(add(transcript, 0xbe60)))
                mstore(add(transcript, 0xbf60), mload(add(transcript, 0xbe80)))
                mstore(add(transcript, 0xbf80), mload(add(transcript, 0xbee0)))
                mstore(add(transcript, 0xbfa0), mload(add(transcript, 0xbf00)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xbf40),
                            0x80,
                            add(transcript, 0xbf40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xbfc0), mload(add(transcript, 0x220)))
                mstore(add(transcript, 0xbfe0), mload(add(transcript, 0x240)))
                mstore(add(transcript, 0xc000), mload(add(transcript, 0x8540)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xbfc0),
                            0x60,
                            add(transcript, 0xbfc0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc020), mload(add(transcript, 0xbf40)))
                mstore(add(transcript, 0xc040), mload(add(transcript, 0xbf60)))
                mstore(add(transcript, 0xc060), mload(add(transcript, 0xbfc0)))
                mstore(add(transcript, 0xc080), mload(add(transcript, 0xbfe0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc020),
                            0x80,
                            add(transcript, 0xc020),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc0a0), mload(add(transcript, 0x560)))
                mstore(add(transcript, 0xc0c0), mload(add(transcript, 0x580)))
                mstore(add(transcript, 0xc0e0), mload(add(transcript, 0x8560)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xc0a0),
                            0x60,
                            add(transcript, 0xc0a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc100), mload(add(transcript, 0xc020)))
                mstore(add(transcript, 0xc120), mload(add(transcript, 0xc040)))
                mstore(add(transcript, 0xc140), mload(add(transcript, 0xc0a0)))
                mstore(add(transcript, 0xc160), mload(add(transcript, 0xc0c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc100),
                            0x80,
                            add(transcript, 0xc100),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc180), mload(add(transcript, 0x5a0)))
                mstore(add(transcript, 0xc1a0), mload(add(transcript, 0x5c0)))
                mstore(add(transcript, 0xc1c0), mload(add(transcript, 0x8640)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xc180),
                            0x60,
                            add(transcript, 0xc180),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc1e0), mload(add(transcript, 0xc100)))
                mstore(add(transcript, 0xc200), mload(add(transcript, 0xc120)))
                mstore(add(transcript, 0xc220), mload(add(transcript, 0xc180)))
                mstore(add(transcript, 0xc240), mload(add(transcript, 0xc1a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc1e0),
                            0x80,
                            add(transcript, 0xc1e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc260), mload(add(transcript, 0x5e0)))
                mstore(add(transcript, 0xc280), mload(add(transcript, 0x600)))
                mstore(add(transcript, 0xc2a0), mload(add(transcript, 0xa440)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xc260),
                            0x60,
                            add(transcript, 0xc260),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc2c0), mload(add(transcript, 0xc1e0)))
                mstore(add(transcript, 0xc2e0), mload(add(transcript, 0xc200)))
                mstore(add(transcript, 0xc300), mload(add(transcript, 0xc260)))
                mstore(add(transcript, 0xc320), mload(add(transcript, 0xc280)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc2c0),
                            0x80,
                            add(transcript, 0xc2c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc340), mload(add(transcript, 0x260)))
                mstore(add(transcript, 0xc360), mload(add(transcript, 0x280)))
                mstore(add(transcript, 0xc380), mload(add(transcript, 0xa460)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xc340),
                            0x60,
                            add(transcript, 0xc340),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc3a0), mload(add(transcript, 0xc2c0)))
                mstore(add(transcript, 0xc3c0), mload(add(transcript, 0xc2e0)))
                mstore(add(transcript, 0xc3e0), mload(add(transcript, 0xc340)))
                mstore(add(transcript, 0xc400), mload(add(transcript, 0xc360)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc3a0),
                            0x80,
                            add(transcript, 0xc3a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc420), mload(add(transcript, 0x2a0)))
                mstore(add(transcript, 0xc440), mload(add(transcript, 0x2c0)))
                mstore(add(transcript, 0xc460), mload(add(transcript, 0xa480)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xc420),
                            0x60,
                            add(transcript, 0xc420),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc480), mload(add(transcript, 0xc3a0)))
                mstore(add(transcript, 0xc4a0), mload(add(transcript, 0xc3c0)))
                mstore(add(transcript, 0xc4c0), mload(add(transcript, 0xc420)))
                mstore(add(transcript, 0xc4e0), mload(add(transcript, 0xc440)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc480),
                            0x80,
                            add(transcript, 0xc480),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc500), mload(add(transcript, 0x2e0)))
                mstore(add(transcript, 0xc520), mload(add(transcript, 0x300)))
                mstore(add(transcript, 0xc540), mload(add(transcript, 0xa4a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xc500),
                            0x60,
                            add(transcript, 0xc500),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc560), mload(add(transcript, 0xc480)))
                mstore(add(transcript, 0xc580), mload(add(transcript, 0xc4a0)))
                mstore(add(transcript, 0xc5a0), mload(add(transcript, 0xc500)))
                mstore(add(transcript, 0xc5c0), mload(add(transcript, 0xc520)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc560),
                            0x80,
                            add(transcript, 0xc560),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc5e0), mload(add(transcript, 0x320)))
                mstore(add(transcript, 0xc600), mload(add(transcript, 0x340)))
                mstore(add(transcript, 0xc620), mload(add(transcript, 0xa4c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xc5e0),
                            0x60,
                            add(transcript, 0xc5e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc640), mload(add(transcript, 0xc560)))
                mstore(add(transcript, 0xc660), mload(add(transcript, 0xc580)))
                mstore(add(transcript, 0xc680), mload(add(transcript, 0xc5e0)))
                mstore(add(transcript, 0xc6a0), mload(add(transcript, 0xc600)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc640),
                            0x80,
                            add(transcript, 0xc640),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc6c0), mload(add(transcript, 0x360)))
                mstore(add(transcript, 0xc6e0), mload(add(transcript, 0x380)))
                mstore(add(transcript, 0xc700), mload(add(transcript, 0xa4e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xc6c0),
                            0x60,
                            add(transcript, 0xc6c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc720), mload(add(transcript, 0xc640)))
                mstore(add(transcript, 0xc740), mload(add(transcript, 0xc660)))
                mstore(add(transcript, 0xc760), mload(add(transcript, 0xc6c0)))
                mstore(add(transcript, 0xc780), mload(add(transcript, 0xc6e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc720),
                            0x80,
                            add(transcript, 0xc720),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc7a0), mload(add(transcript, 0x3a0)))
                mstore(add(transcript, 0xc7c0), mload(add(transcript, 0x3c0)))
                mstore(add(transcript, 0xc7e0), mload(add(transcript, 0xa500)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xc7a0),
                            0x60,
                            add(transcript, 0xc7a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc800), mload(add(transcript, 0xc720)))
                mstore(add(transcript, 0xc820), mload(add(transcript, 0xc740)))
                mstore(add(transcript, 0xc840), mload(add(transcript, 0xc7a0)))
                mstore(add(transcript, 0xc860), mload(add(transcript, 0xc7c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc800),
                            0x80,
                            add(transcript, 0xc800),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc880), mload(add(transcript, 0x3e0)))
                mstore(add(transcript, 0xc8a0), mload(add(transcript, 0x400)))
                mstore(add(transcript, 0xc8c0), mload(add(transcript, 0xa520)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xc880),
                            0x60,
                            add(transcript, 0xc880),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc8e0), mload(add(transcript, 0xc800)))
                mstore(add(transcript, 0xc900), mload(add(transcript, 0xc820)))
                mstore(add(transcript, 0xc920), mload(add(transcript, 0xc880)))
                mstore(add(transcript, 0xc940), mload(add(transcript, 0xc8a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc8e0),
                            0x80,
                            add(transcript, 0xc8e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc960), mload(add(transcript, 0x420)))
                mstore(add(transcript, 0xc980), mload(add(transcript, 0x440)))
                mstore(add(transcript, 0xc9a0), mload(add(transcript, 0xa540)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xc960),
                            0x60,
                            add(transcript, 0xc960),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xc9c0), mload(add(transcript, 0xc8e0)))
                mstore(add(transcript, 0xc9e0), mload(add(transcript, 0xc900)))
                mstore(add(transcript, 0xca00), mload(add(transcript, 0xc960)))
                mstore(add(transcript, 0xca20), mload(add(transcript, 0xc980)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xc9c0),
                            0x80,
                            add(transcript, 0xc9c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xca40), mload(add(transcript, 0x460)))
                mstore(add(transcript, 0xca60), mload(add(transcript, 0x480)))
                mstore(add(transcript, 0xca80), mload(add(transcript, 0xa560)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xca40),
                            0x60,
                            add(transcript, 0xca40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcaa0), mload(add(transcript, 0xc9c0)))
                mstore(add(transcript, 0xcac0), mload(add(transcript, 0xc9e0)))
                mstore(add(transcript, 0xcae0), mload(add(transcript, 0xca40)))
                mstore(add(transcript, 0xcb00), mload(add(transcript, 0xca60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xcaa0),
                            0x80,
                            add(transcript, 0xcaa0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcb20), mload(add(transcript, 0x4a0)))
                mstore(add(transcript, 0xcb40), mload(add(transcript, 0x4c0)))
                mstore(add(transcript, 0xcb60), mload(add(transcript, 0xa580)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xcb20),
                            0x60,
                            add(transcript, 0xcb20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcb80), mload(add(transcript, 0xcaa0)))
                mstore(add(transcript, 0xcba0), mload(add(transcript, 0xcac0)))
                mstore(add(transcript, 0xcbc0), mload(add(transcript, 0xcb20)))
                mstore(add(transcript, 0xcbe0), mload(add(transcript, 0xcb40)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xcb80),
                            0x80,
                            add(transcript, 0xcb80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcc00), mload(add(transcript, 0x4e0)))
                mstore(add(transcript, 0xcc20), mload(add(transcript, 0x500)))
                mstore(add(transcript, 0xcc40), mload(add(transcript, 0xa5a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xcc00),
                            0x60,
                            add(transcript, 0xcc00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcc60), mload(add(transcript, 0xcb80)))
                mstore(add(transcript, 0xcc80), mload(add(transcript, 0xcba0)))
                mstore(add(transcript, 0xcca0), mload(add(transcript, 0xcc00)))
                mstore(add(transcript, 0xccc0), mload(add(transcript, 0xcc20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xcc60),
                            0x80,
                            add(transcript, 0xcc60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcce0), mload(add(transcript, 0x520)))
                mstore(add(transcript, 0xcd00), mload(add(transcript, 0x540)))
                mstore(add(transcript, 0xcd20), mload(add(transcript, 0xa5c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xcce0),
                            0x60,
                            add(transcript, 0xcce0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcd40), mload(add(transcript, 0xcc60)))
                mstore(add(transcript, 0xcd60), mload(add(transcript, 0xcc80)))
                mstore(add(transcript, 0xcd80), mload(add(transcript, 0xcce0)))
                mstore(add(transcript, 0xcda0), mload(add(transcript, 0xcd00)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xcd40),
                            0x80,
                            add(transcript, 0xcd40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcdc0), mload(add(transcript, 0x6c0)))
                mstore(add(transcript, 0xcde0), mload(add(transcript, 0x6e0)))
                mstore(add(transcript, 0xce00), mload(add(transcript, 0xa5e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xcdc0),
                            0x60,
                            add(transcript, 0xcdc0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xce20), mload(add(transcript, 0xcd40)))
                mstore(add(transcript, 0xce40), mload(add(transcript, 0xcd60)))
                mstore(add(transcript, 0xce60), mload(add(transcript, 0xcdc0)))
                mstore(add(transcript, 0xce80), mload(add(transcript, 0xcde0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xce20),
                            0x80,
                            add(transcript, 0xce20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcea0), mload(add(transcript, 0x740)))
                mstore(add(transcript, 0xcec0), mload(add(transcript, 0x760)))
                mstore(add(transcript, 0xcee0), mload(add(transcript, 0xa600)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xcea0),
                            0x60,
                            add(transcript, 0xcea0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcf00), mload(add(transcript, 0xce20)))
                mstore(add(transcript, 0xcf20), mload(add(transcript, 0xce40)))
                mstore(add(transcript, 0xcf40), mload(add(transcript, 0xcea0)))
                mstore(add(transcript, 0xcf60), mload(add(transcript, 0xcec0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xcf00),
                            0x80,
                            add(transcript, 0xcf00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcf80), mload(add(transcript, 0x7c0)))
                mstore(add(transcript, 0xcfa0), mload(add(transcript, 0x7e0)))
                mstore(add(transcript, 0xcfc0), mload(add(transcript, 0xa620)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xcf80),
                            0x60,
                            add(transcript, 0xcf80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xcfe0), mload(add(transcript, 0xcf00)))
                mstore(add(transcript, 0xd000), mload(add(transcript, 0xcf20)))
                mstore(add(transcript, 0xd020), mload(add(transcript, 0xcf80)))
                mstore(add(transcript, 0xd040), mload(add(transcript, 0xcfa0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xcfe0),
                            0x80,
                            add(transcript, 0xcfe0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd060), mload(add(transcript, 0x840)))
                mstore(add(transcript, 0xd080), mload(add(transcript, 0x860)))
                mstore(add(transcript, 0xd0a0), mload(add(transcript, 0xa640)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xd060),
                            0x60,
                            add(transcript, 0xd060),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd0c0), mload(add(transcript, 0xcfe0)))
                mstore(add(transcript, 0xd0e0), mload(add(transcript, 0xd000)))
                mstore(add(transcript, 0xd100), mload(add(transcript, 0xd060)))
                mstore(add(transcript, 0xd120), mload(add(transcript, 0xd080)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xd0c0),
                            0x80,
                            add(transcript, 0xd0c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd140), mload(add(transcript, 0x8c0)))
                mstore(add(transcript, 0xd160), mload(add(transcript, 0x8e0)))
                mstore(add(transcript, 0xd180), mload(add(transcript, 0xa660)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xd140),
                            0x60,
                            add(transcript, 0xd140),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd1a0), mload(add(transcript, 0xd0c0)))
                mstore(add(transcript, 0xd1c0), mload(add(transcript, 0xd0e0)))
                mstore(add(transcript, 0xd1e0), mload(add(transcript, 0xd140)))
                mstore(add(transcript, 0xd200), mload(add(transcript, 0xd160)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xd1a0),
                            0x80,
                            add(transcript, 0xd1a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd220), mload(add(transcript, 0x940)))
                mstore(add(transcript, 0xd240), mload(add(transcript, 0x960)))
                mstore(add(transcript, 0xd260), mload(add(transcript, 0xa680)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xd220),
                            0x60,
                            add(transcript, 0xd220),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd280), mload(add(transcript, 0xd1a0)))
                mstore(add(transcript, 0xd2a0), mload(add(transcript, 0xd1c0)))
                mstore(add(transcript, 0xd2c0), mload(add(transcript, 0xd220)))
                mstore(add(transcript, 0xd2e0), mload(add(transcript, 0xd240)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xd280),
                            0x80,
                            add(transcript, 0xd280),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd300), mload(add(transcript, 0x9c0)))
                mstore(add(transcript, 0xd320), mload(add(transcript, 0x9e0)))
                mstore(add(transcript, 0xd340), mload(add(transcript, 0xa6a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xd300),
                            0x60,
                            add(transcript, 0xd300),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd360), mload(add(transcript, 0xd280)))
                mstore(add(transcript, 0xd380), mload(add(transcript, 0xd2a0)))
                mstore(add(transcript, 0xd3a0), mload(add(transcript, 0xd300)))
                mstore(add(transcript, 0xd3c0), mload(add(transcript, 0xd320)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xd360),
                            0x80,
                            add(transcript, 0xd360),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xd3e0),
                    0x180fe65835b7d5e4c89b8cc32c05746d8db0c77d66511a33f1cbfc44774a45b2
                )
                mstore(
                    add(transcript, 0xd400),
                    0x0b93f0b7d4535c23572ef6a70ac616324ed80b124ef4245b956de5c010ac9d3c
                )
                mstore(add(transcript, 0xd420), mload(add(transcript, 0xa6c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xd3e0),
                            0x60,
                            add(transcript, 0xd3e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd440), mload(add(transcript, 0xd360)))
                mstore(add(transcript, 0xd460), mload(add(transcript, 0xd380)))
                mstore(add(transcript, 0xd480), mload(add(transcript, 0xd3e0)))
                mstore(add(transcript, 0xd4a0), mload(add(transcript, 0xd400)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xd440),
                            0x80,
                            add(transcript, 0xd440),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xd4c0),
                    0x05a845c4c22f91b6cc0b30cb372e74f702e001dd6d989b9be83d36ea0ed72e31
                )
                mstore(
                    add(transcript, 0xd4e0),
                    0x07fc43631c1955a50124821f0c8e226ac44d3f943000ba917e593f6b38788cea
                )
                mstore(add(transcript, 0xd500), mload(add(transcript, 0xa6e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xd4c0),
                            0x60,
                            add(transcript, 0xd4c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd520), mload(add(transcript, 0xd440)))
                mstore(add(transcript, 0xd540), mload(add(transcript, 0xd460)))
                mstore(add(transcript, 0xd560), mload(add(transcript, 0xd4c0)))
                mstore(add(transcript, 0xd580), mload(add(transcript, 0xd4e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xd520),
                            0x80,
                            add(transcript, 0xd520),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xd5a0),
                    0x01006c6df4dcf6932626c982fb307a3fd40035f3fd090b65862ad36b571b1567
                )
                mstore(
                    add(transcript, 0xd5c0),
                    0x07bee68eaec9d157b789663e666329969f812fbf955098cfba108af446eb00a4
                )
                mstore(add(transcript, 0xd5e0), mload(add(transcript, 0xa700)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xd5a0),
                            0x60,
                            add(transcript, 0xd5a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd600), mload(add(transcript, 0xd520)))
                mstore(add(transcript, 0xd620), mload(add(transcript, 0xd540)))
                mstore(add(transcript, 0xd640), mload(add(transcript, 0xd5a0)))
                mstore(add(transcript, 0xd660), mload(add(transcript, 0xd5c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xd600),
                            0x80,
                            add(transcript, 0xd600),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xd680),
                    0x108469236caf32294570edb150dba1ebfc4da8ebd6c2bee87030d7f5fb7da3b3
                )
                mstore(
                    add(transcript, 0xd6a0),
                    0x0590aff224a5e9f7857dc1ee72a1386eacf630155f871228d1e57e70f1ce2e61
                )
                mstore(add(transcript, 0xd6c0), mload(add(transcript, 0xa720)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xd680),
                            0x60,
                            add(transcript, 0xd680),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd6e0), mload(add(transcript, 0xd600)))
                mstore(add(transcript, 0xd700), mload(add(transcript, 0xd620)))
                mstore(add(transcript, 0xd720), mload(add(transcript, 0xd680)))
                mstore(add(transcript, 0xd740), mload(add(transcript, 0xd6a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xd6e0),
                            0x80,
                            add(transcript, 0xd6e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xd760),
                    0x0a02f287e92a1ca81a4abf4f70cbf9d23c752755ada42fd23f4f301e01e16aa9
                )
                mstore(
                    add(transcript, 0xd780),
                    0x15cf7a25179af354815266a9f90b2822be649eaf8da2761c55776ff8c3cf8ae7
                )
                mstore(add(transcript, 0xd7a0), mload(add(transcript, 0xa740)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xd760),
                            0x60,
                            add(transcript, 0xd760),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd7c0), mload(add(transcript, 0xd6e0)))
                mstore(add(transcript, 0xd7e0), mload(add(transcript, 0xd700)))
                mstore(add(transcript, 0xd800), mload(add(transcript, 0xd760)))
                mstore(add(transcript, 0xd820), mload(add(transcript, 0xd780)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xd7c0),
                            0x80,
                            add(transcript, 0xd7c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xd840),
                    0x2e9a0f10d9ae7033b8128f95555b52256c0acb37936ad5358deefb0e0f1cdf36
                )
                mstore(
                    add(transcript, 0xd860),
                    0x18728ef076ab3830048cf6021de43925976c47b27688ba81b0f561d5162291c2
                )
                mstore(add(transcript, 0xd880), mload(add(transcript, 0xa760)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xd840),
                            0x60,
                            add(transcript, 0xd840),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd8a0), mload(add(transcript, 0xd7c0)))
                mstore(add(transcript, 0xd8c0), mload(add(transcript, 0xd7e0)))
                mstore(add(transcript, 0xd8e0), mload(add(transcript, 0xd840)))
                mstore(add(transcript, 0xd900), mload(add(transcript, 0xd860)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xd8a0),
                            0x80,
                            add(transcript, 0xd8a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xd920),
                    0x1fb728ee26cea705bc1a87e103087f85604cb74e434aa8bc938b6a429f419f34
                )
                mstore(
                    add(transcript, 0xd940),
                    0x2bc10a51500bfb8e03aed000251efba6f1c28bbf2b0e87a8aa1a85a6652aeb1a
                )
                mstore(add(transcript, 0xd960), mload(add(transcript, 0xa780)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xd920),
                            0x60,
                            add(transcript, 0xd920),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xd980), mload(add(transcript, 0xd8a0)))
                mstore(add(transcript, 0xd9a0), mload(add(transcript, 0xd8c0)))
                mstore(add(transcript, 0xd9c0), mload(add(transcript, 0xd920)))
                mstore(add(transcript, 0xd9e0), mload(add(transcript, 0xd940)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xd980),
                            0x80,
                            add(transcript, 0xd980),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xda00),
                    0x1afebbf839d3f68a2c1e26d748987f0519cc464dd6c9cbed7e760de144c93166
                )
                mstore(
                    add(transcript, 0xda20),
                    0x22167adc9831abe8ec9e0bfe65cbb6eed4e699731c8335b6e3c7fd541074a1d9
                )
                mstore(add(transcript, 0xda40), mload(add(transcript, 0xa7a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xda00),
                            0x60,
                            add(transcript, 0xda00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xda60), mload(add(transcript, 0xd980)))
                mstore(add(transcript, 0xda80), mload(add(transcript, 0xd9a0)))
                mstore(add(transcript, 0xdaa0), mload(add(transcript, 0xda00)))
                mstore(add(transcript, 0xdac0), mload(add(transcript, 0xda20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0xda60),
                            0x80,
                            add(transcript, 0xda60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0xdae0),
                    0x19d0a325253643a68e6d4252a68ff4e57cb85f042019f6e0c6cbac245ad4116b
                )
                mstore(
                    add(transcript, 0xdb00),
                    0x03984fac41ca22b34633d836c819e0f03810f5d0cde1ffab5f94b913de5b8174
                )
                mstore(add(transcript, 0xdb20), mload(add(transcript, 0xa7c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0xdae0),
                            0x60,
                            add(transcript, 0xdae0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0xdb40), mload(add(transcript, 0xda60)))
                mstore(add(transcript, 0xdb60), mload(add(transcript, 0xda80)))
                mstore(add(transcript, 0xdb80), mload(add(transcript, 0xdae0)))
                mstore(add(transcript, 0xdba0), mload(add(transcript, 0xdb00)))
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
