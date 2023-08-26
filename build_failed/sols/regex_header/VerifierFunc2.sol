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
        bytes32[2776] memory transcript;
        // require(_transcript.length == 2776, "transcript length is not 2776");
        if(_transcript.length != 0) {
            transcript = abi.decode(_transcript, (bytes32[2776]));
        }
        // for(uint i=0; i<_transcript.length; i++) {
        //     transcript[i] = _transcript[i];
        // }
        assembly {{
            
            let f_p
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
    {            let prod := mload(add(transcript, 0x9740))                prod := mulmod(mload(add(transcript, 0x9780)), prod, f_q)                mstore(add(transcript, 0x9860), prod)                            prod := mulmod(mload(add(transcript, 0x97c0)), prod, f_q)                mstore(add(transcript, 0x9880), prod)                            prod := mulmod(mload(add(transcript, 0x9800)), prod, f_q)                mstore(add(transcript, 0x98a0), prod)                            prod := mulmod(mload(add(transcript, 0x9840)), prod, f_q)                mstore(add(transcript, 0x98c0), prod)                    }
mstore(add(transcript, 0x9900), 32)
mstore(add(transcript, 0x9920), 32)
mstore(add(transcript, 0x9940), 32)
mstore(add(transcript, 0x9960), mload(add(transcript, 0x98c0)))
mstore(add(transcript, 0x9980), 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(add(transcript, 0x99a0), 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, add(transcript, 0x9900), 0xc0, add(transcript, 0x98e0), 0x20), 1), success)
{                        let inv := mload(add(transcript, 0x98e0))            let v                            v := mload(add(transcript, 0x9840))                    mstore(add(transcript, 0x9840), mulmod(mload(add(transcript, 0x98a0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x9800))                    mstore(add(transcript, 0x9800), mulmod(mload(add(transcript, 0x9880)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x97c0))                    mstore(add(transcript, 0x97c0), mulmod(mload(add(transcript, 0x9860)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x9780))                    mstore(add(transcript, 0x9780), mulmod(mload(add(transcript, 0x9740)), inv, f_q))                    inv := mulmod(v, inv, f_q)                mstore(add(transcript, 0x9740), inv)        }
mstore(add(transcript, 0x99c0), mulmod(mload(add(transcript, 0x9760)), mload(add(transcript, 0x9780)), f_q))
mstore(add(transcript, 0x99e0), mulmod(mload(add(transcript, 0x97a0)), mload(add(transcript, 0x97c0)), f_q))
mstore(add(transcript, 0x9a00), mulmod(mload(add(transcript, 0x97e0)), mload(add(transcript, 0x9800)), f_q))
mstore(add(transcript, 0x9a20), mulmod(mload(add(transcript, 0x9820)), mload(add(transcript, 0x9840)), f_q))
mstore(add(transcript, 0x9a40), mulmod(mload(add(transcript, 0x26a0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9a60), mulmod(mload(add(transcript, 0x9a40)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9a80), mulmod(mload(add(transcript, 0x9a60)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9aa0), mulmod(mload(add(transcript, 0x9a80)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9ac0), mulmod(mload(add(transcript, 0x9aa0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9ae0), mulmod(mload(add(transcript, 0x9ac0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9b00), mulmod(mload(add(transcript, 0x9ae0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9b20), mulmod(mload(add(transcript, 0x9b00)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9b40), mulmod(mload(add(transcript, 0x9b20)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9b60), mulmod(mload(add(transcript, 0x9b40)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9b80), mulmod(mload(add(transcript, 0x9b60)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9ba0), mulmod(mload(add(transcript, 0x9b80)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9bc0), mulmod(mload(add(transcript, 0x9ba0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9be0), mulmod(mload(add(transcript, 0x9bc0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9c00), mulmod(mload(add(transcript, 0x9be0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9c20), mulmod(mload(add(transcript, 0x9c00)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9c40), mulmod(mload(add(transcript, 0x9c20)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9c60), mulmod(mload(add(transcript, 0x9c40)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9c80), mulmod(mload(add(transcript, 0x9c60)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9ca0), mulmod(mload(add(transcript, 0x9c80)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9cc0), mulmod(mload(add(transcript, 0x9ca0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9ce0), mulmod(mload(add(transcript, 0x9cc0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9d00), mulmod(mload(add(transcript, 0x9ce0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9d20), mulmod(mload(add(transcript, 0x9d00)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9d40), mulmod(mload(add(transcript, 0x9d20)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9d60), mulmod(mload(add(transcript, 0x9d40)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9d80), mulmod(mload(add(transcript, 0x9d60)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9da0), mulmod(mload(add(transcript, 0x9d80)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9dc0), mulmod(mload(add(transcript, 0x9da0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9de0), mulmod(mload(add(transcript, 0x9dc0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9e00), mulmod(mload(add(transcript, 0x9de0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9e20), mulmod(mload(add(transcript, 0x9e00)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9e40), mulmod(mload(add(transcript, 0x9e20)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9e60), mulmod(mload(add(transcript, 0x9e40)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9e80), mulmod(mload(add(transcript, 0x9e60)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9ea0), mulmod(mload(add(transcript, 0x9e80)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9ec0), mulmod(mload(add(transcript, 0x9ea0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9ee0), mulmod(mload(add(transcript, 0x9ec0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9f00), mulmod(mload(add(transcript, 0x9ee0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9f20), mulmod(mload(add(transcript, 0x9f00)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9f40), mulmod(mload(add(transcript, 0x9f20)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9f60), mulmod(mload(add(transcript, 0x9f40)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9f80), mulmod(mload(add(transcript, 0x9f60)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9fa0), mulmod(mload(add(transcript, 0x9f80)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9fc0), mulmod(mload(add(transcript, 0x9fa0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0x9fe0), mulmod(mload(add(transcript, 0x9fc0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa000), mulmod(mload(add(transcript, 0x9fe0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa020), mulmod(mload(add(transcript, 0xa000)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa040), mulmod(mload(add(transcript, 0xa020)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa060), mulmod(mload(add(transcript, 0xa040)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa080), mulmod(mload(add(transcript, 0xa060)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa0a0), mulmod(mload(add(transcript, 0xa080)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa0c0), mulmod(mload(add(transcript, 0xa0a0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa0e0), mulmod(mload(add(transcript, 0xa0c0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa100), mulmod(mload(add(transcript, 0xa0e0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa120), mulmod(mload(add(transcript, 0xa100)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa140), mulmod(mload(add(transcript, 0xa120)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa160), mulmod(mload(add(transcript, 0xa140)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa180), mulmod(mload(add(transcript, 0xa160)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa1a0), mulmod(mload(add(transcript, 0xa180)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa1c0), mulmod(mload(add(transcript, 0xa1a0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa1e0), mulmod(mload(add(transcript, 0xa1c0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa200), mulmod(mload(add(transcript, 0xa1e0)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa220), mulmod(mload(add(transcript, 0xa200)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa240), mulmod(mload(add(transcript, 0xa220)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa260), mulmod(mload(add(transcript, 0xa240)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa280), mulmod(mload(add(transcript, 0xa260)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa2a0), mulmod(mload(add(transcript, 0xa280)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa2c0), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xa2e0), mulmod(mload(add(transcript, 0xa2c0)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xa300), mulmod(mload(add(transcript, 0xa2e0)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xa320), mulmod(mload(add(transcript, 0xa300)), mload(add(transcript, 0x2700)), f_q))
{            let result := mulmod(mload(add(transcript, 0x11a0)), mload(add(transcript, 0x9240)), f_q)result := addmod(mulmod(mload(add(transcript, 0x11c0)), mload(add(transcript, 0x9260)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x11e0)), mload(add(transcript, 0x9280)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1200)), mload(add(transcript, 0x92a0)), f_q), result, f_q)mstore(add(transcript, 0xa340), result)        }
mstore(add(transcript, 0xa360), mulmod(mload(add(transcript, 0xa340)), mload(add(transcript, 0x9740)), f_q))
mstore(add(transcript, 0xa380), mulmod(sub(f_q, mload(add(transcript, 0xa360))), 1, f_q))
{            let result := mulmod(mload(add(transcript, 0x1220)), mload(add(transcript, 0x9240)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1240)), mload(add(transcript, 0x9260)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1260)), mload(add(transcript, 0x9280)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1280)), mload(add(transcript, 0x92a0)), f_q), result, f_q)mstore(add(transcript, 0xa3a0), result)        }
mstore(add(transcript, 0xa3c0), mulmod(mload(add(transcript, 0xa3a0)), mload(add(transcript, 0x9740)), f_q))
mstore(add(transcript, 0xa3e0), mulmod(sub(f_q, mload(add(transcript, 0xa3c0))), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa400), mulmod(1, mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xa420), addmod(mload(add(transcript, 0xa380)), mload(add(transcript, 0xa3e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x12a0)), mload(add(transcript, 0x9240)), f_q)result := addmod(mulmod(mload(add(transcript, 0x12c0)), mload(add(transcript, 0x9260)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x12e0)), mload(add(transcript, 0x9280)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1300)), mload(add(transcript, 0x92a0)), f_q), result, f_q)mstore(add(transcript, 0xa440), result)        }
mstore(add(transcript, 0xa460), mulmod(mload(add(transcript, 0xa440)), mload(add(transcript, 0x9740)), f_q))
mstore(add(transcript, 0xa480), mulmod(sub(f_q, mload(add(transcript, 0xa460))), mload(add(transcript, 0x9a40)), f_q))
mstore(add(transcript, 0xa4a0), mulmod(1, mload(add(transcript, 0x9a40)), f_q))
mstore(add(transcript, 0xa4c0), addmod(mload(add(transcript, 0xa420)), mload(add(transcript, 0xa480)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1320)), mload(add(transcript, 0x9240)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1340)), mload(add(transcript, 0x9260)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1360)), mload(add(transcript, 0x9280)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1380)), mload(add(transcript, 0x92a0)), f_q), result, f_q)mstore(add(transcript, 0xa4e0), result)        }
mstore(add(transcript, 0xa500), mulmod(mload(add(transcript, 0xa4e0)), mload(add(transcript, 0x9740)), f_q))
mstore(add(transcript, 0xa520), mulmod(sub(f_q, mload(add(transcript, 0xa500))), mload(add(transcript, 0x9a60)), f_q))
mstore(add(transcript, 0xa540), mulmod(1, mload(add(transcript, 0x9a60)), f_q))
mstore(add(transcript, 0xa560), addmod(mload(add(transcript, 0xa4c0)), mload(add(transcript, 0xa520)), f_q))
{            let result := mulmod(mload(add(transcript, 0x13a0)), mload(add(transcript, 0x9240)), f_q)result := addmod(mulmod(mload(add(transcript, 0x13c0)), mload(add(transcript, 0x9260)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x13e0)), mload(add(transcript, 0x9280)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1400)), mload(add(transcript, 0x92a0)), f_q), result, f_q)mstore(add(transcript, 0xa580), result)        }
mstore(add(transcript, 0xa5a0), mulmod(mload(add(transcript, 0xa580)), mload(add(transcript, 0x9740)), f_q))
mstore(add(transcript, 0xa5c0), mulmod(sub(f_q, mload(add(transcript, 0xa5a0))), mload(add(transcript, 0x9a80)), f_q))
mstore(add(transcript, 0xa5e0), mulmod(1, mload(add(transcript, 0x9a80)), f_q))
mstore(add(transcript, 0xa600), addmod(mload(add(transcript, 0xa560)), mload(add(transcript, 0xa5c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1420)), mload(add(transcript, 0x9240)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1440)), mload(add(transcript, 0x9260)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1460)), mload(add(transcript, 0x9280)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1480)), mload(add(transcript, 0x92a0)), f_q), result, f_q)mstore(add(transcript, 0xa620), result)        }
mstore(add(transcript, 0xa640), mulmod(mload(add(transcript, 0xa620)), mload(add(transcript, 0x9740)), f_q))
mstore(add(transcript, 0xa660), mulmod(sub(f_q, mload(add(transcript, 0xa640))), mload(add(transcript, 0x9aa0)), f_q))
mstore(add(transcript, 0xa680), mulmod(1, mload(add(transcript, 0x9aa0)), f_q))
mstore(add(transcript, 0xa6a0), addmod(mload(add(transcript, 0xa600)), mload(add(transcript, 0xa660)), f_q))
{            let result := mulmod(mload(add(transcript, 0x14a0)), mload(add(transcript, 0x9240)), f_q)result := addmod(mulmod(mload(add(transcript, 0x14c0)), mload(add(transcript, 0x9260)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x14e0)), mload(add(transcript, 0x9280)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1500)), mload(add(transcript, 0x92a0)), f_q), result, f_q)mstore(add(transcript, 0xa6c0), result)        }
mstore(add(transcript, 0xa6e0), mulmod(mload(add(transcript, 0xa6c0)), mload(add(transcript, 0x9740)), f_q))
mstore(add(transcript, 0xa700), mulmod(sub(f_q, mload(add(transcript, 0xa6e0))), mload(add(transcript, 0x9ac0)), f_q))
mstore(add(transcript, 0xa720), mulmod(1, mload(add(transcript, 0x9ac0)), f_q))
mstore(add(transcript, 0xa740), addmod(mload(add(transcript, 0xa6a0)), mload(add(transcript, 0xa700)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1520)), mload(add(transcript, 0x9240)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1540)), mload(add(transcript, 0x9260)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1560)), mload(add(transcript, 0x9280)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1580)), mload(add(transcript, 0x92a0)), f_q), result, f_q)mstore(add(transcript, 0xa760), result)        }
mstore(add(transcript, 0xa780), mulmod(mload(add(transcript, 0xa760)), mload(add(transcript, 0x9740)), f_q))
mstore(add(transcript, 0xa7a0), mulmod(sub(f_q, mload(add(transcript, 0xa780))), mload(add(transcript, 0x9ae0)), f_q))
mstore(add(transcript, 0xa7c0), mulmod(1, mload(add(transcript, 0x9ae0)), f_q))
mstore(add(transcript, 0xa7e0), addmod(mload(add(transcript, 0xa740)), mload(add(transcript, 0xa7a0)), f_q))
mstore(add(transcript, 0xa800), mulmod(mload(add(transcript, 0xa7e0)), 1, f_q))
mstore(add(transcript, 0xa820), mulmod(mload(add(transcript, 0xa400)), 1, f_q))
mstore(add(transcript, 0xa840), mulmod(mload(add(transcript, 0xa4a0)), 1, f_q))
mstore(add(transcript, 0xa860), mulmod(mload(add(transcript, 0xa540)), 1, f_q))
mstore(add(transcript, 0xa880), mulmod(mload(add(transcript, 0xa5e0)), 1, f_q))
mstore(add(transcript, 0xa8a0), mulmod(mload(add(transcript, 0xa680)), 1, f_q))
mstore(add(transcript, 0xa8c0), mulmod(mload(add(transcript, 0xa720)), 1, f_q))
mstore(add(transcript, 0xa8e0), mulmod(mload(add(transcript, 0xa7c0)), 1, f_q))
mstore(add(transcript, 0xa900), mulmod(1, mload(add(transcript, 0x9760)), f_q))
{            let result := mulmod(mload(add(transcript, 0x15a0)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1780)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xa920), result)        }
mstore(add(transcript, 0xa940), mulmod(mload(add(transcript, 0xa920)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xa960), mulmod(sub(f_q, mload(add(transcript, 0xa940))), 1, f_q))
mstore(add(transcript, 0xa980), mulmod(mload(add(transcript, 0xa900)), 1, f_q))
{            let result := mulmod(mload(add(transcript, 0x15c0)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x17c0)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xa9a0), result)        }
mstore(add(transcript, 0xa9c0), mulmod(mload(add(transcript, 0xa9a0)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xa9e0), mulmod(sub(f_q, mload(add(transcript, 0xa9c0))), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xaa00), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xaa20), addmod(mload(add(transcript, 0xa960)), mload(add(transcript, 0xa9e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x15e0)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1800)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xaa40), result)        }
mstore(add(transcript, 0xaa60), mulmod(mload(add(transcript, 0xaa40)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xaa80), mulmod(sub(f_q, mload(add(transcript, 0xaa60))), mload(add(transcript, 0x9a40)), f_q))
mstore(add(transcript, 0xaaa0), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9a40)), f_q))
mstore(add(transcript, 0xaac0), addmod(mload(add(transcript, 0xaa20)), mload(add(transcript, 0xaa80)), f_q))
{            let result := mulmod(mload(add(transcript, 0x16c0)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x17a0)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xaae0), result)        }
mstore(add(transcript, 0xab00), mulmod(mload(add(transcript, 0xaae0)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xab20), mulmod(sub(f_q, mload(add(transcript, 0xab00))), mload(add(transcript, 0x9a60)), f_q))
mstore(add(transcript, 0xab40), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9a60)), f_q))
mstore(add(transcript, 0xab60), addmod(mload(add(transcript, 0xaac0)), mload(add(transcript, 0xab20)), f_q))
{            let result := mulmod(mload(add(transcript, 0x16e0)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x17e0)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xab80), result)        }
mstore(add(transcript, 0xaba0), mulmod(mload(add(transcript, 0xab80)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xabc0), mulmod(sub(f_q, mload(add(transcript, 0xaba0))), mload(add(transcript, 0x9a80)), f_q))
mstore(add(transcript, 0xabe0), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9a80)), f_q))
mstore(add(transcript, 0xac00), addmod(mload(add(transcript, 0xab60)), mload(add(transcript, 0xabc0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1700)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1820)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xac20), result)        }
mstore(add(transcript, 0xac40), mulmod(mload(add(transcript, 0xac20)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xac60), mulmod(sub(f_q, mload(add(transcript, 0xac40))), mload(add(transcript, 0x9aa0)), f_q))
mstore(add(transcript, 0xac80), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9aa0)), f_q))
mstore(add(transcript, 0xaca0), addmod(mload(add(transcript, 0xac00)), mload(add(transcript, 0xac60)), f_q))
{            let result := mulmod(mload(add(transcript, 0x20a0)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x20c0)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xacc0), result)        }
mstore(add(transcript, 0xace0), mulmod(mload(add(transcript, 0xacc0)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xad00), mulmod(sub(f_q, mload(add(transcript, 0xace0))), mload(add(transcript, 0x9ac0)), f_q))
mstore(add(transcript, 0xad20), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9ac0)), f_q))
mstore(add(transcript, 0xad40), addmod(mload(add(transcript, 0xaca0)), mload(add(transcript, 0xad00)), f_q))
{            let result := mulmod(mload(add(transcript, 0x20e0)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2100)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xad60), result)        }
mstore(add(transcript, 0xad80), mulmod(mload(add(transcript, 0xad60)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xada0), mulmod(sub(f_q, mload(add(transcript, 0xad80))), mload(add(transcript, 0x9ae0)), f_q))
mstore(add(transcript, 0xadc0), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9ae0)), f_q))
mstore(add(transcript, 0xade0), addmod(mload(add(transcript, 0xad40)), mload(add(transcript, 0xada0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2180)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x21a0)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xae00), result)        }
mstore(add(transcript, 0xae20), mulmod(mload(add(transcript, 0xae00)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xae40), mulmod(sub(f_q, mload(add(transcript, 0xae20))), mload(add(transcript, 0x9b00)), f_q))
mstore(add(transcript, 0xae60), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9b00)), f_q))
mstore(add(transcript, 0xae80), addmod(mload(add(transcript, 0xade0)), mload(add(transcript, 0xae40)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2220)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2240)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xaea0), result)        }
mstore(add(transcript, 0xaec0), mulmod(mload(add(transcript, 0xaea0)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xaee0), mulmod(sub(f_q, mload(add(transcript, 0xaec0))), mload(add(transcript, 0x9b20)), f_q))
mstore(add(transcript, 0xaf00), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9b20)), f_q))
mstore(add(transcript, 0xaf20), addmod(mload(add(transcript, 0xae80)), mload(add(transcript, 0xaee0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x22c0)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x22e0)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xaf40), result)        }
mstore(add(transcript, 0xaf60), mulmod(mload(add(transcript, 0xaf40)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xaf80), mulmod(sub(f_q, mload(add(transcript, 0xaf60))), mload(add(transcript, 0x9b40)), f_q))
mstore(add(transcript, 0xafa0), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9b40)), f_q))
mstore(add(transcript, 0xafc0), addmod(mload(add(transcript, 0xaf20)), mload(add(transcript, 0xaf80)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2360)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2380)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xafe0), result)        }
mstore(add(transcript, 0xb000), mulmod(mload(add(transcript, 0xafe0)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xb020), mulmod(sub(f_q, mload(add(transcript, 0xb000))), mload(add(transcript, 0x9b60)), f_q))
mstore(add(transcript, 0xb040), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9b60)), f_q))
mstore(add(transcript, 0xb060), addmod(mload(add(transcript, 0xafc0)), mload(add(transcript, 0xb020)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2400)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2420)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xb080), result)        }
mstore(add(transcript, 0xb0a0), mulmod(mload(add(transcript, 0xb080)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xb0c0), mulmod(sub(f_q, mload(add(transcript, 0xb0a0))), mload(add(transcript, 0x9b80)), f_q))
mstore(add(transcript, 0xb0e0), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9b80)), f_q))
mstore(add(transcript, 0xb100), addmod(mload(add(transcript, 0xb060)), mload(add(transcript, 0xb0c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x24a0)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x24c0)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xb120), result)        }
mstore(add(transcript, 0xb140), mulmod(mload(add(transcript, 0xb120)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xb160), mulmod(sub(f_q, mload(add(transcript, 0xb140))), mload(add(transcript, 0x9ba0)), f_q))
mstore(add(transcript, 0xb180), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9ba0)), f_q))
mstore(add(transcript, 0xb1a0), addmod(mload(add(transcript, 0xb100)), mload(add(transcript, 0xb160)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2540)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2560)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xb1c0), result)        }
mstore(add(transcript, 0xb1e0), mulmod(mload(add(transcript, 0xb1c0)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xb200), mulmod(sub(f_q, mload(add(transcript, 0xb1e0))), mload(add(transcript, 0x9bc0)), f_q))
mstore(add(transcript, 0xb220), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9bc0)), f_q))
mstore(add(transcript, 0xb240), addmod(mload(add(transcript, 0xb1a0)), mload(add(transcript, 0xb200)), f_q))
{            let result := mulmod(mload(add(transcript, 0x25e0)), mload(add(transcript, 0x9340)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2600)), mload(add(transcript, 0x9360)), f_q), result, f_q)mstore(add(transcript, 0xb260), result)        }
mstore(add(transcript, 0xb280), mulmod(mload(add(transcript, 0xb260)), mload(add(transcript, 0x99c0)), f_q))
mstore(add(transcript, 0xb2a0), mulmod(sub(f_q, mload(add(transcript, 0xb280))), mload(add(transcript, 0x9be0)), f_q))
mstore(add(transcript, 0xb2c0), mulmod(mload(add(transcript, 0xa900)), mload(add(transcript, 0x9be0)), f_q))
mstore(add(transcript, 0xb2e0), addmod(mload(add(transcript, 0xb240)), mload(add(transcript, 0xb2a0)), f_q))
mstore(add(transcript, 0xb300), mulmod(mload(add(transcript, 0xb2e0)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb320), mulmod(mload(add(transcript, 0xa980)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb340), mulmod(mload(add(transcript, 0xaa00)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb360), mulmod(mload(add(transcript, 0xaaa0)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb380), mulmod(mload(add(transcript, 0xab40)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb3a0), mulmod(mload(add(transcript, 0xabe0)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb3c0), mulmod(mload(add(transcript, 0xac80)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb3e0), mulmod(mload(add(transcript, 0xad20)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb400), mulmod(mload(add(transcript, 0xadc0)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb420), mulmod(mload(add(transcript, 0xae60)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb440), mulmod(mload(add(transcript, 0xaf00)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb460), mulmod(mload(add(transcript, 0xafa0)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb480), mulmod(mload(add(transcript, 0xb040)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb4a0), mulmod(mload(add(transcript, 0xb0e0)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb4c0), mulmod(mload(add(transcript, 0xb180)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb4e0), mulmod(mload(add(transcript, 0xb220)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb500), mulmod(mload(add(transcript, 0xb2c0)), mload(add(transcript, 0x2700)), f_q))
mstore(add(transcript, 0xb520), addmod(mload(add(transcript, 0xa800)), mload(add(transcript, 0xb300)), f_q))
mstore(add(transcript, 0xb540), mulmod(1, mload(add(transcript, 0x97a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1600)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xb560), result)        }
mstore(add(transcript, 0xb580), mulmod(mload(add(transcript, 0xb560)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xb5a0), mulmod(sub(f_q, mload(add(transcript, 0xb580))), 1, f_q))
mstore(add(transcript, 0xb5c0), mulmod(mload(add(transcript, 0xb540)), 1, f_q))
{            let result := mulmod(mload(add(transcript, 0x1620)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xb5e0), result)        }
mstore(add(transcript, 0xb600), mulmod(mload(add(transcript, 0xb5e0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xb620), mulmod(sub(f_q, mload(add(transcript, 0xb600))), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xb640), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x26a0)), f_q))
mstore(add(transcript, 0xb660), addmod(mload(add(transcript, 0xb5a0)), mload(add(transcript, 0xb620)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1640)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xb680), result)        }
mstore(add(transcript, 0xb6a0), mulmod(mload(add(transcript, 0xb680)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xb6c0), mulmod(sub(f_q, mload(add(transcript, 0xb6a0))), mload(add(transcript, 0x9a40)), f_q))
mstore(add(transcript, 0xb6e0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9a40)), f_q))
mstore(add(transcript, 0xb700), addmod(mload(add(transcript, 0xb660)), mload(add(transcript, 0xb6c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1660)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xb720), result)        }
mstore(add(transcript, 0xb740), mulmod(mload(add(transcript, 0xb720)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xb760), mulmod(sub(f_q, mload(add(transcript, 0xb740))), mload(add(transcript, 0x9a60)), f_q))
mstore(add(transcript, 0xb780), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9a60)), f_q))
mstore(add(transcript, 0xb7a0), addmod(mload(add(transcript, 0xb700)), mload(add(transcript, 0xb760)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1680)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xb7c0), result)        }
mstore(add(transcript, 0xb7e0), mulmod(mload(add(transcript, 0xb7c0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xb800), mulmod(sub(f_q, mload(add(transcript, 0xb7e0))), mload(add(transcript, 0x9a80)), f_q))
mstore(add(transcript, 0xb820), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9a80)), f_q))
mstore(add(transcript, 0xb840), addmod(mload(add(transcript, 0xb7a0)), mload(add(transcript, 0xb800)), f_q))
{            let result := mulmod(mload(add(transcript, 0x16a0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xb860), result)        }
mstore(add(transcript, 0xb880), mulmod(mload(add(transcript, 0xb860)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xb8a0), mulmod(sub(f_q, mload(add(transcript, 0xb880))), mload(add(transcript, 0x9aa0)), f_q))
mstore(add(transcript, 0xb8c0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9aa0)), f_q))
mstore(add(transcript, 0xb8e0), addmod(mload(add(transcript, 0xb840)), mload(add(transcript, 0xb8a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1720)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xb900), result)        }
mstore(add(transcript, 0xb920), mulmod(mload(add(transcript, 0xb900)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xb940), mulmod(sub(f_q, mload(add(transcript, 0xb920))), mload(add(transcript, 0x9ac0)), f_q))
mstore(add(transcript, 0xb960), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9ac0)), f_q))
mstore(add(transcript, 0xb980), addmod(mload(add(transcript, 0xb8e0)), mload(add(transcript, 0xb940)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2160)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xb9a0), result)        }
mstore(add(transcript, 0xb9c0), mulmod(mload(add(transcript, 0xb9a0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xb9e0), mulmod(sub(f_q, mload(add(transcript, 0xb9c0))), mload(add(transcript, 0x9ae0)), f_q))
mstore(add(transcript, 0xba00), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9ae0)), f_q))
mstore(add(transcript, 0xba20), addmod(mload(add(transcript, 0xb980)), mload(add(transcript, 0xb9e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2200)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xba40), result)        }
mstore(add(transcript, 0xba60), mulmod(mload(add(transcript, 0xba40)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xba80), mulmod(sub(f_q, mload(add(transcript, 0xba60))), mload(add(transcript, 0x9b00)), f_q))
mstore(add(transcript, 0xbaa0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9b00)), f_q))
mstore(add(transcript, 0xbac0), addmod(mload(add(transcript, 0xba20)), mload(add(transcript, 0xba80)), f_q))
{            let result := mulmod(mload(add(transcript, 0x22a0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xbae0), result)        }
mstore(add(transcript, 0xbb00), mulmod(mload(add(transcript, 0xbae0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xbb20), mulmod(sub(f_q, mload(add(transcript, 0xbb00))), mload(add(transcript, 0x9b20)), f_q))
mstore(add(transcript, 0xbb40), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9b20)), f_q))
mstore(add(transcript, 0xbb60), addmod(mload(add(transcript, 0xbac0)), mload(add(transcript, 0xbb20)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2340)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xbb80), result)        }
mstore(add(transcript, 0xbba0), mulmod(mload(add(transcript, 0xbb80)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xbbc0), mulmod(sub(f_q, mload(add(transcript, 0xbba0))), mload(add(transcript, 0x9b40)), f_q))
mstore(add(transcript, 0xbbe0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9b40)), f_q))
mstore(add(transcript, 0xbc00), addmod(mload(add(transcript, 0xbb60)), mload(add(transcript, 0xbbc0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x23e0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xbc20), result)        }
mstore(add(transcript, 0xbc40), mulmod(mload(add(transcript, 0xbc20)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xbc60), mulmod(sub(f_q, mload(add(transcript, 0xbc40))), mload(add(transcript, 0x9b60)), f_q))
mstore(add(transcript, 0xbc80), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9b60)), f_q))
mstore(add(transcript, 0xbca0), addmod(mload(add(transcript, 0xbc00)), mload(add(transcript, 0xbc60)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2480)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xbcc0), result)        }
mstore(add(transcript, 0xbce0), mulmod(mload(add(transcript, 0xbcc0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xbd00), mulmod(sub(f_q, mload(add(transcript, 0xbce0))), mload(add(transcript, 0x9b80)), f_q))
mstore(add(transcript, 0xbd20), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9b80)), f_q))
mstore(add(transcript, 0xbd40), addmod(mload(add(transcript, 0xbca0)), mload(add(transcript, 0xbd00)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2520)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xbd60), result)        }
mstore(add(transcript, 0xbd80), mulmod(mload(add(transcript, 0xbd60)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xbda0), mulmod(sub(f_q, mload(add(transcript, 0xbd80))), mload(add(transcript, 0x9ba0)), f_q))
mstore(add(transcript, 0xbdc0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9ba0)), f_q))
mstore(add(transcript, 0xbde0), addmod(mload(add(transcript, 0xbd40)), mload(add(transcript, 0xbda0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x25c0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xbe00), result)        }
mstore(add(transcript, 0xbe20), mulmod(mload(add(transcript, 0xbe00)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xbe40), mulmod(sub(f_q, mload(add(transcript, 0xbe20))), mload(add(transcript, 0x9bc0)), f_q))
mstore(add(transcript, 0xbe60), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9bc0)), f_q))
mstore(add(transcript, 0xbe80), addmod(mload(add(transcript, 0xbde0)), mload(add(transcript, 0xbe40)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2660)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xbea0), result)        }
mstore(add(transcript, 0xbec0), mulmod(mload(add(transcript, 0xbea0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xbee0), mulmod(sub(f_q, mload(add(transcript, 0xbec0))), mload(add(transcript, 0x9be0)), f_q))
mstore(add(transcript, 0xbf00), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9be0)), f_q))
mstore(add(transcript, 0xbf20), addmod(mload(add(transcript, 0xbe80)), mload(add(transcript, 0xbee0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1840)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xbf40), result)        }
mstore(add(transcript, 0xbf60), mulmod(mload(add(transcript, 0xbf40)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xbf80), mulmod(sub(f_q, mload(add(transcript, 0xbf60))), mload(add(transcript, 0x9c00)), f_q))
mstore(add(transcript, 0xbfa0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9c00)), f_q))
mstore(add(transcript, 0xbfc0), addmod(mload(add(transcript, 0xbf20)), mload(add(transcript, 0xbf80)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1860)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xbfe0), result)        }
mstore(add(transcript, 0xc000), mulmod(mload(add(transcript, 0xbfe0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc020), mulmod(sub(f_q, mload(add(transcript, 0xc000))), mload(add(transcript, 0x9c20)), f_q))
mstore(add(transcript, 0xc040), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9c20)), f_q))
mstore(add(transcript, 0xc060), addmod(mload(add(transcript, 0xbfc0)), mload(add(transcript, 0xc020)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1880)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc080), result)        }
mstore(add(transcript, 0xc0a0), mulmod(mload(add(transcript, 0xc080)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc0c0), mulmod(sub(f_q, mload(add(transcript, 0xc0a0))), mload(add(transcript, 0x9c40)), f_q))
mstore(add(transcript, 0xc0e0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9c40)), f_q))
mstore(add(transcript, 0xc100), addmod(mload(add(transcript, 0xc060)), mload(add(transcript, 0xc0c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x18a0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc120), result)        }
mstore(add(transcript, 0xc140), mulmod(mload(add(transcript, 0xc120)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc160), mulmod(sub(f_q, mload(add(transcript, 0xc140))), mload(add(transcript, 0x9c60)), f_q))
mstore(add(transcript, 0xc180), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9c60)), f_q))
mstore(add(transcript, 0xc1a0), addmod(mload(add(transcript, 0xc100)), mload(add(transcript, 0xc160)), f_q))
{            let result := mulmod(mload(add(transcript, 0x18c0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc1c0), result)        }
mstore(add(transcript, 0xc1e0), mulmod(mload(add(transcript, 0xc1c0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc200), mulmod(sub(f_q, mload(add(transcript, 0xc1e0))), mload(add(transcript, 0x9c80)), f_q))
mstore(add(transcript, 0xc220), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9c80)), f_q))
mstore(add(transcript, 0xc240), addmod(mload(add(transcript, 0xc1a0)), mload(add(transcript, 0xc200)), f_q))
{            let result := mulmod(mload(add(transcript, 0x18e0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc260), result)        }
mstore(add(transcript, 0xc280), mulmod(mload(add(transcript, 0xc260)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc2a0), mulmod(sub(f_q, mload(add(transcript, 0xc280))), mload(add(transcript, 0x9ca0)), f_q))
mstore(add(transcript, 0xc2c0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9ca0)), f_q))
mstore(add(transcript, 0xc2e0), addmod(mload(add(transcript, 0xc240)), mload(add(transcript, 0xc2a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1900)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc300), result)        }
mstore(add(transcript, 0xc320), mulmod(mload(add(transcript, 0xc300)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc340), mulmod(sub(f_q, mload(add(transcript, 0xc320))), mload(add(transcript, 0x9cc0)), f_q))
mstore(add(transcript, 0xc360), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9cc0)), f_q))
mstore(add(transcript, 0xc380), addmod(mload(add(transcript, 0xc2e0)), mload(add(transcript, 0xc340)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1920)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc3a0), result)        }
mstore(add(transcript, 0xc3c0), mulmod(mload(add(transcript, 0xc3a0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc3e0), mulmod(sub(f_q, mload(add(transcript, 0xc3c0))), mload(add(transcript, 0x9ce0)), f_q))
mstore(add(transcript, 0xc400), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9ce0)), f_q))
mstore(add(transcript, 0xc420), addmod(mload(add(transcript, 0xc380)), mload(add(transcript, 0xc3e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1940)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc440), result)        }
mstore(add(transcript, 0xc460), mulmod(mload(add(transcript, 0xc440)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc480), mulmod(sub(f_q, mload(add(transcript, 0xc460))), mload(add(transcript, 0x9d00)), f_q))
mstore(add(transcript, 0xc4a0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9d00)), f_q))
mstore(add(transcript, 0xc4c0), addmod(mload(add(transcript, 0xc420)), mload(add(transcript, 0xc480)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1960)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc4e0), result)        }
mstore(add(transcript, 0xc500), mulmod(mload(add(transcript, 0xc4e0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc520), mulmod(sub(f_q, mload(add(transcript, 0xc500))), mload(add(transcript, 0x9d20)), f_q))
mstore(add(transcript, 0xc540), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9d20)), f_q))
mstore(add(transcript, 0xc560), addmod(mload(add(transcript, 0xc4c0)), mload(add(transcript, 0xc520)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1980)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc580), result)        }
mstore(add(transcript, 0xc5a0), mulmod(mload(add(transcript, 0xc580)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc5c0), mulmod(sub(f_q, mload(add(transcript, 0xc5a0))), mload(add(transcript, 0x9d40)), f_q))
mstore(add(transcript, 0xc5e0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9d40)), f_q))
mstore(add(transcript, 0xc600), addmod(mload(add(transcript, 0xc560)), mload(add(transcript, 0xc5c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x19a0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc620), result)        }
mstore(add(transcript, 0xc640), mulmod(mload(add(transcript, 0xc620)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc660), mulmod(sub(f_q, mload(add(transcript, 0xc640))), mload(add(transcript, 0x9d60)), f_q))
mstore(add(transcript, 0xc680), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9d60)), f_q))
mstore(add(transcript, 0xc6a0), addmod(mload(add(transcript, 0xc600)), mload(add(transcript, 0xc660)), f_q))
{            let result := mulmod(mload(add(transcript, 0x19c0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc6c0), result)        }
mstore(add(transcript, 0xc6e0), mulmod(mload(add(transcript, 0xc6c0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc700), mulmod(sub(f_q, mload(add(transcript, 0xc6e0))), mload(add(transcript, 0x9d80)), f_q))
mstore(add(transcript, 0xc720), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9d80)), f_q))
mstore(add(transcript, 0xc740), addmod(mload(add(transcript, 0xc6a0)), mload(add(transcript, 0xc700)), f_q))
{            let result := mulmod(mload(add(transcript, 0x19e0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc760), result)        }
mstore(add(transcript, 0xc780), mulmod(mload(add(transcript, 0xc760)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc7a0), mulmod(sub(f_q, mload(add(transcript, 0xc780))), mload(add(transcript, 0x9da0)), f_q))
mstore(add(transcript, 0xc7c0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9da0)), f_q))
mstore(add(transcript, 0xc7e0), addmod(mload(add(transcript, 0xc740)), mload(add(transcript, 0xc7a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1a00)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc800), result)        }
mstore(add(transcript, 0xc820), mulmod(mload(add(transcript, 0xc800)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc840), mulmod(sub(f_q, mload(add(transcript, 0xc820))), mload(add(transcript, 0x9dc0)), f_q))
mstore(add(transcript, 0xc860), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9dc0)), f_q))
mstore(add(transcript, 0xc880), addmod(mload(add(transcript, 0xc7e0)), mload(add(transcript, 0xc840)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1a20)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc8a0), result)        }
mstore(add(transcript, 0xc8c0), mulmod(mload(add(transcript, 0xc8a0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc8e0), mulmod(sub(f_q, mload(add(transcript, 0xc8c0))), mload(add(transcript, 0x9de0)), f_q))
mstore(add(transcript, 0xc900), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9de0)), f_q))
mstore(add(transcript, 0xc920), addmod(mload(add(transcript, 0xc880)), mload(add(transcript, 0xc8e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1a40)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xc940), result)        }
mstore(add(transcript, 0xc960), mulmod(mload(add(transcript, 0xc940)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xc980), mulmod(sub(f_q, mload(add(transcript, 0xc960))), mload(add(transcript, 0x9e00)), f_q))
mstore(add(transcript, 0xc9a0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9e00)), f_q))
mstore(add(transcript, 0xc9c0), addmod(mload(add(transcript, 0xc920)), mload(add(transcript, 0xc980)), f_q))
mstore(add(transcript, 0xc9e0), addmod(mload(add(transcript, 0xc540)), mload(add(transcript, 0xc9a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1a60)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xca00), result)        }
mstore(add(transcript, 0xca20), mulmod(mload(add(transcript, 0xca00)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xca40), mulmod(sub(f_q, mload(add(transcript, 0xca20))), mload(add(transcript, 0x9e20)), f_q))
mstore(add(transcript, 0xca60), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9e20)), f_q))
mstore(add(transcript, 0xca80), addmod(mload(add(transcript, 0xc9c0)), mload(add(transcript, 0xca40)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1a80)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xcaa0), result)        }
mstore(add(transcript, 0xcac0), mulmod(mload(add(transcript, 0xcaa0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xcae0), mulmod(sub(f_q, mload(add(transcript, 0xcac0))), mload(add(transcript, 0x9e40)), f_q))
mstore(add(transcript, 0xcb00), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9e40)), f_q))
mstore(add(transcript, 0xcb20), addmod(mload(add(transcript, 0xca80)), mload(add(transcript, 0xcae0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1aa0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xcb40), result)        }
mstore(add(transcript, 0xcb60), mulmod(mload(add(transcript, 0xcb40)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xcb80), mulmod(sub(f_q, mload(add(transcript, 0xcb60))), mload(add(transcript, 0x9e60)), f_q))
mstore(add(transcript, 0xcba0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9e60)), f_q))
mstore(add(transcript, 0xcbc0), addmod(mload(add(transcript, 0xcb20)), mload(add(transcript, 0xcb80)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1ac0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xcbe0), result)        }
mstore(add(transcript, 0xcc00), mulmod(mload(add(transcript, 0xcbe0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xcc20), mulmod(sub(f_q, mload(add(transcript, 0xcc00))), mload(add(transcript, 0x9e80)), f_q))
mstore(add(transcript, 0xcc40), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9e80)), f_q))
mstore(add(transcript, 0xcc60), addmod(mload(add(transcript, 0xcbc0)), mload(add(transcript, 0xcc20)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1ae0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xcc80), result)        }
mstore(add(transcript, 0xcca0), mulmod(mload(add(transcript, 0xcc80)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xccc0), mulmod(sub(f_q, mload(add(transcript, 0xcca0))), mload(add(transcript, 0x9ea0)), f_q))
mstore(add(transcript, 0xcce0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9ea0)), f_q))
mstore(add(transcript, 0xcd00), addmod(mload(add(transcript, 0xcc60)), mload(add(transcript, 0xccc0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1b00)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xcd20), result)        }
mstore(add(transcript, 0xcd40), mulmod(mload(add(transcript, 0xcd20)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xcd60), mulmod(sub(f_q, mload(add(transcript, 0xcd40))), mload(add(transcript, 0x9ec0)), f_q))
mstore(add(transcript, 0xcd80), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9ec0)), f_q))
mstore(add(transcript, 0xcda0), addmod(mload(add(transcript, 0xcd00)), mload(add(transcript, 0xcd60)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1b20)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xcdc0), result)        }
mstore(add(transcript, 0xcde0), mulmod(mload(add(transcript, 0xcdc0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xce00), mulmod(sub(f_q, mload(add(transcript, 0xcde0))), mload(add(transcript, 0x9ee0)), f_q))
mstore(add(transcript, 0xce20), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9ee0)), f_q))
mstore(add(transcript, 0xce40), addmod(mload(add(transcript, 0xcda0)), mload(add(transcript, 0xce00)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1b40)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xce60), result)        }
mstore(add(transcript, 0xce80), mulmod(mload(add(transcript, 0xce60)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xcea0), mulmod(sub(f_q, mload(add(transcript, 0xce80))), mload(add(transcript, 0x9f00)), f_q))
mstore(add(transcript, 0xcec0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9f00)), f_q))
mstore(add(transcript, 0xcee0), addmod(mload(add(transcript, 0xce40)), mload(add(transcript, 0xcea0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1b60)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xcf00), result)        }
mstore(add(transcript, 0xcf20), mulmod(mload(add(transcript, 0xcf00)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xcf40), mulmod(sub(f_q, mload(add(transcript, 0xcf20))), mload(add(transcript, 0x9f20)), f_q))
mstore(add(transcript, 0xcf60), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9f20)), f_q))
mstore(add(transcript, 0xcf80), addmod(mload(add(transcript, 0xcee0)), mload(add(transcript, 0xcf40)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1b80)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xcfa0), result)        }
mstore(add(transcript, 0xcfc0), mulmod(mload(add(transcript, 0xcfa0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xcfe0), mulmod(sub(f_q, mload(add(transcript, 0xcfc0))), mload(add(transcript, 0x9f40)), f_q))
mstore(add(transcript, 0xd000), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9f40)), f_q))
mstore(add(transcript, 0xd020), addmod(mload(add(transcript, 0xcf80)), mload(add(transcript, 0xcfe0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1bc0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd040), result)        }
mstore(add(transcript, 0xd060), mulmod(mload(add(transcript, 0xd040)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd080), mulmod(sub(f_q, mload(add(transcript, 0xd060))), mload(add(transcript, 0x9f60)), f_q))
mstore(add(transcript, 0xd0a0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9f60)), f_q))
mstore(add(transcript, 0xd0c0), addmod(mload(add(transcript, 0xd020)), mload(add(transcript, 0xd080)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1be0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd0e0), result)        }
mstore(add(transcript, 0xd100), mulmod(mload(add(transcript, 0xd0e0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd120), mulmod(sub(f_q, mload(add(transcript, 0xd100))), mload(add(transcript, 0x9f80)), f_q))
mstore(add(transcript, 0xd140), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9f80)), f_q))
mstore(add(transcript, 0xd160), addmod(mload(add(transcript, 0xd0c0)), mload(add(transcript, 0xd120)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1c00)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd180), result)        }
mstore(add(transcript, 0xd1a0), mulmod(mload(add(transcript, 0xd180)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd1c0), mulmod(sub(f_q, mload(add(transcript, 0xd1a0))), mload(add(transcript, 0x9fa0)), f_q))
mstore(add(transcript, 0xd1e0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9fa0)), f_q))
mstore(add(transcript, 0xd200), addmod(mload(add(transcript, 0xd160)), mload(add(transcript, 0xd1c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1c20)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd220), result)        }
mstore(add(transcript, 0xd240), mulmod(mload(add(transcript, 0xd220)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd260), mulmod(sub(f_q, mload(add(transcript, 0xd240))), mload(add(transcript, 0x9fc0)), f_q))
mstore(add(transcript, 0xd280), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9fc0)), f_q))
mstore(add(transcript, 0xd2a0), addmod(mload(add(transcript, 0xd200)), mload(add(transcript, 0xd260)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1c40)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd2c0), result)        }
mstore(add(transcript, 0xd2e0), mulmod(mload(add(transcript, 0xd2c0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd300), mulmod(sub(f_q, mload(add(transcript, 0xd2e0))), mload(add(transcript, 0x9fe0)), f_q))
mstore(add(transcript, 0xd320), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0x9fe0)), f_q))
mstore(add(transcript, 0xd340), addmod(mload(add(transcript, 0xd2a0)), mload(add(transcript, 0xd300)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1c60)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd360), result)        }
mstore(add(transcript, 0xd380), mulmod(mload(add(transcript, 0xd360)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd3a0), mulmod(sub(f_q, mload(add(transcript, 0xd380))), mload(add(transcript, 0xa000)), f_q))
mstore(add(transcript, 0xd3c0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa000)), f_q))
mstore(add(transcript, 0xd3e0), addmod(mload(add(transcript, 0xd340)), mload(add(transcript, 0xd3a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1c80)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd400), result)        }
mstore(add(transcript, 0xd420), mulmod(mload(add(transcript, 0xd400)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd440), mulmod(sub(f_q, mload(add(transcript, 0xd420))), mload(add(transcript, 0xa020)), f_q))
mstore(add(transcript, 0xd460), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa020)), f_q))
mstore(add(transcript, 0xd480), addmod(mload(add(transcript, 0xd3e0)), mload(add(transcript, 0xd440)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1ca0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd4a0), result)        }
mstore(add(transcript, 0xd4c0), mulmod(mload(add(transcript, 0xd4a0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd4e0), mulmod(sub(f_q, mload(add(transcript, 0xd4c0))), mload(add(transcript, 0xa040)), f_q))
mstore(add(transcript, 0xd500), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa040)), f_q))
mstore(add(transcript, 0xd520), addmod(mload(add(transcript, 0xd480)), mload(add(transcript, 0xd4e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1cc0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd540), result)        }
mstore(add(transcript, 0xd560), mulmod(mload(add(transcript, 0xd540)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd580), mulmod(sub(f_q, mload(add(transcript, 0xd560))), mload(add(transcript, 0xa060)), f_q))
mstore(add(transcript, 0xd5a0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa060)), f_q))
mstore(add(transcript, 0xd5c0), addmod(mload(add(transcript, 0xd520)), mload(add(transcript, 0xd580)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1ce0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd5e0), result)        }
mstore(add(transcript, 0xd600), mulmod(mload(add(transcript, 0xd5e0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd620), mulmod(sub(f_q, mload(add(transcript, 0xd600))), mload(add(transcript, 0xa080)), f_q))
mstore(add(transcript, 0xd640), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa080)), f_q))
mstore(add(transcript, 0xd660), addmod(mload(add(transcript, 0xd5c0)), mload(add(transcript, 0xd620)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1d00)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd680), result)        }
mstore(add(transcript, 0xd6a0), mulmod(mload(add(transcript, 0xd680)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd6c0), mulmod(sub(f_q, mload(add(transcript, 0xd6a0))), mload(add(transcript, 0xa0a0)), f_q))
mstore(add(transcript, 0xd6e0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa0a0)), f_q))
mstore(add(transcript, 0xd700), addmod(mload(add(transcript, 0xd660)), mload(add(transcript, 0xd6c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1d20)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd720), result)        }
mstore(add(transcript, 0xd740), mulmod(mload(add(transcript, 0xd720)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd760), mulmod(sub(f_q, mload(add(transcript, 0xd740))), mload(add(transcript, 0xa0c0)), f_q))
mstore(add(transcript, 0xd780), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa0c0)), f_q))
mstore(add(transcript, 0xd7a0), addmod(mload(add(transcript, 0xd700)), mload(add(transcript, 0xd760)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1d40)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd7c0), result)        }
mstore(add(transcript, 0xd7e0), mulmod(mload(add(transcript, 0xd7c0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd800), mulmod(sub(f_q, mload(add(transcript, 0xd7e0))), mload(add(transcript, 0xa0e0)), f_q))
mstore(add(transcript, 0xd820), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa0e0)), f_q))
mstore(add(transcript, 0xd840), addmod(mload(add(transcript, 0xd7a0)), mload(add(transcript, 0xd800)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1d60)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd860), result)        }
mstore(add(transcript, 0xd880), mulmod(mload(add(transcript, 0xd860)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd8a0), mulmod(sub(f_q, mload(add(transcript, 0xd880))), mload(add(transcript, 0xa100)), f_q))
mstore(add(transcript, 0xd8c0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa100)), f_q))
mstore(add(transcript, 0xd8e0), addmod(mload(add(transcript, 0xd840)), mload(add(transcript, 0xd8a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1d80)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd900), result)        }
mstore(add(transcript, 0xd920), mulmod(mload(add(transcript, 0xd900)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd940), mulmod(sub(f_q, mload(add(transcript, 0xd920))), mload(add(transcript, 0xa120)), f_q))
mstore(add(transcript, 0xd960), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa120)), f_q))
mstore(add(transcript, 0xd980), addmod(mload(add(transcript, 0xd8e0)), mload(add(transcript, 0xd940)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1da0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xd9a0), result)        }
mstore(add(transcript, 0xd9c0), mulmod(mload(add(transcript, 0xd9a0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xd9e0), mulmod(sub(f_q, mload(add(transcript, 0xd9c0))), mload(add(transcript, 0xa140)), f_q))
mstore(add(transcript, 0xda00), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa140)), f_q))
mstore(add(transcript, 0xda20), addmod(mload(add(transcript, 0xd980)), mload(add(transcript, 0xd9e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1dc0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xda40), result)        }
mstore(add(transcript, 0xda60), mulmod(mload(add(transcript, 0xda40)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xda80), mulmod(sub(f_q, mload(add(transcript, 0xda60))), mload(add(transcript, 0xa160)), f_q))
mstore(add(transcript, 0xdaa0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa160)), f_q))
mstore(add(transcript, 0xdac0), addmod(mload(add(transcript, 0xda20)), mload(add(transcript, 0xda80)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1de0)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xdae0), result)        }
mstore(add(transcript, 0xdb00), mulmod(mload(add(transcript, 0xdae0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xdb20), mulmod(sub(f_q, mload(add(transcript, 0xdb00))), mload(add(transcript, 0xa180)), f_q))
mstore(add(transcript, 0xdb40), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa180)), f_q))
mstore(add(transcript, 0xdb60), addmod(mload(add(transcript, 0xdac0)), mload(add(transcript, 0xdb20)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1e00)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xdb80), result)        }
mstore(add(transcript, 0xdba0), mulmod(mload(add(transcript, 0xdb80)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xdbc0), mulmod(sub(f_q, mload(add(transcript, 0xdba0))), mload(add(transcript, 0xa1a0)), f_q))
mstore(add(transcript, 0xdbe0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa1a0)), f_q))
mstore(add(transcript, 0xdc00), addmod(mload(add(transcript, 0xdb60)), mload(add(transcript, 0xdbc0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1e20)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xdc20), result)        }
mstore(add(transcript, 0xdc40), mulmod(mload(add(transcript, 0xdc20)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xdc60), mulmod(sub(f_q, mload(add(transcript, 0xdc40))), mload(add(transcript, 0xa1c0)), f_q))
mstore(add(transcript, 0xdc80), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa1c0)), f_q))
mstore(add(transcript, 0xdca0), addmod(mload(add(transcript, 0xdc00)), mload(add(transcript, 0xdc60)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1e40)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xdcc0), result)        }
mstore(add(transcript, 0xdce0), mulmod(mload(add(transcript, 0xdcc0)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xdd00), mulmod(sub(f_q, mload(add(transcript, 0xdce0))), mload(add(transcript, 0xa1e0)), f_q))
mstore(add(transcript, 0xdd20), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa1e0)), f_q))
mstore(add(transcript, 0xdd40), addmod(mload(add(transcript, 0xdca0)), mload(add(transcript, 0xdd00)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1e60)), mload(add(transcript, 0x9380)), f_q)mstore(add(transcript, 0xdd60), result)        }
mstore(add(transcript, 0xdd80), mulmod(mload(add(transcript, 0xdd60)), mload(add(transcript, 0x99e0)), f_q))
mstore(add(transcript, 0xdda0), mulmod(sub(f_q, mload(add(transcript, 0xdd80))), mload(add(transcript, 0xa200)), f_q))
mstore(add(transcript, 0xddc0), mulmod(mload(add(transcript, 0xb540)), mload(add(transcript, 0xa200)), f_q))
mstore(add(transcript, 0xdde0), addmod(mload(add(transcript, 0xdd40)), mload(add(transcript, 0xdda0)), f_q))

        }}
        bytes memory transcriptBytes = abi.encode(transcript);
        // bytes32[] memory newTranscript = new bytes32[](2776);
        // for(uint i=0; i<_transcript.length; i++) {
        //     newTranscript[i] = transcript[i];
        // }
        // require(newTranscript.length == 2776, "newTranscript length is not 2776");
        return (success, transcriptBytes);
    } 
}
