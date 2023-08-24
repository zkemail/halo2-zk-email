// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "../VerifierFuncAbst.sol";

contract VerifierFunc1 is VerifierFuncAbst {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes32[] memory _transcript
    ) public view override returns (bool, bytes32[] memory) {
        bytes32[1606] memory transcript;
        for(uint i=0; i<_transcript.length; i++) {
            transcript[i] = _transcript[i];
        }
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
    mstore(add(transcript, 0x5000), addmod(mload(add(transcript, 0x1660)), mload(add(transcript, 0x640)), f_q))
mstore(add(transcript, 0x5020), mulmod(mload(add(transcript, 0x5000)), mload(add(transcript, 0x4fe0)), f_q))
mstore(add(transcript, 0x5040), mulmod(mload(add(transcript, 0xf80)), mload(add(transcript, 0xf20)), f_q))
mstore(add(transcript, 0x5060), mulmod(mload(add(transcript, 0xea0)), mload(add(transcript, 0x5040)), f_q))
mstore(add(transcript, 0x5080), mulmod(mload(add(transcript, 0x400)), mload(add(transcript, 0x5060)), f_q))
mstore(add(transcript, 0x50a0), addmod(mload(add(transcript, 0x5080)), 18446744073709551615, f_q))
mstore(add(transcript, 0x50c0), mulmod(mload(add(transcript, 0x400)), mload(add(transcript, 0x50a0)), f_q))
mstore(add(transcript, 0x50e0), mulmod(mload(add(transcript, 0xf60)), mload(add(transcript, 0x5040)), f_q))
mstore(add(transcript, 0x5100), addmod(1, sub(f_q, mload(add(transcript, 0x5040))), f_q))
mstore(add(transcript, 0x5120), mulmod(18446744073709551615, mload(add(transcript, 0x5100)), f_q))
mstore(add(transcript, 0x5140), addmod(mload(add(transcript, 0x50e0)), mload(add(transcript, 0x5120)), f_q))
mstore(add(transcript, 0x5160), addmod(mload(add(transcript, 0x50c0)), mload(add(transcript, 0x5140)), f_q))
mstore(add(transcript, 0x5180), addmod(mload(add(transcript, 0x5160)), mload(add(transcript, 0x5e0)), f_q))
mstore(add(transcript, 0x51a0), mulmod(mload(add(transcript, 0x5180)), mload(add(transcript, 0x15e0)), f_q))
mstore(add(transcript, 0x51c0), mulmod(mload(add(transcript, 0x4cc0)), mload(add(transcript, 0x51a0)), f_q))
mstore(add(transcript, 0x51e0), addmod(mload(add(transcript, 0x5020)), sub(f_q, mload(add(transcript, 0x51c0))), f_q))
mstore(add(transcript, 0x5200), mulmod(mload(add(transcript, 0x51e0)), mload(add(transcript, 0x2ee0)), f_q))
mstore(add(transcript, 0x5220), addmod(mload(add(transcript, 0x4fa0)), mload(add(transcript, 0x5200)), f_q))
mstore(add(transcript, 0x5240), mulmod(mload(add(transcript, 0x8a0)), mload(add(transcript, 0x5220)), f_q))
mstore(add(transcript, 0x5260), addmod(mload(add(transcript, 0x1620)), sub(f_q, mload(add(transcript, 0x1660))), f_q))
mstore(add(transcript, 0x5280), mulmod(mload(add(transcript, 0x5260)), mload(add(transcript, 0x1fa0)), f_q))
mstore(add(transcript, 0x52a0), addmod(mload(add(transcript, 0x5240)), mload(add(transcript, 0x5280)), f_q))
mstore(add(transcript, 0x52c0), mulmod(mload(add(transcript, 0x8a0)), mload(add(transcript, 0x52a0)), f_q))
mstore(add(transcript, 0x52e0), mulmod(mload(add(transcript, 0x5260)), mload(add(transcript, 0x2ee0)), f_q))
mstore(add(transcript, 0x5300), addmod(mload(add(transcript, 0x1620)), sub(f_q, mload(add(transcript, 0x1640))), f_q))
mstore(add(transcript, 0x5320), mulmod(mload(add(transcript, 0x5300)), mload(add(transcript, 0x52e0)), f_q))
mstore(add(transcript, 0x5340), addmod(mload(add(transcript, 0x52c0)), mload(add(transcript, 0x5320)), f_q))
mstore(add(transcript, 0x5360), mulmod(mload(add(transcript, 0x1a20)), mload(add(transcript, 0x1a20)), f_q))
mstore(add(transcript, 0x5380), mulmod(mload(add(transcript, 0x5360)), mload(add(transcript, 0x1a20)), f_q))
mstore(add(transcript, 0x53a0), mulmod(mload(add(transcript, 0x5380)), mload(add(transcript, 0x1a20)), f_q))
mstore(add(transcript, 0x53c0), mulmod(mload(add(transcript, 0x53a0)), mload(add(transcript, 0x1a20)), f_q))
mstore(add(transcript, 0x53e0), mulmod(1, mload(add(transcript, 0x1a20)), f_q))
mstore(add(transcript, 0x5400), mulmod(1, mload(add(transcript, 0x5360)), f_q))
mstore(add(transcript, 0x5420), mulmod(1, mload(add(transcript, 0x5380)), f_q))
mstore(add(transcript, 0x5440), mulmod(1, mload(add(transcript, 0x53a0)), f_q))
mstore(add(transcript, 0x5460), mulmod(mload(add(transcript, 0x5340)), mload(add(transcript, 0x1a40)), f_q))
mstore(add(transcript, 0x5480), mulmod(mload(add(transcript, 0x1820)), mload(add(transcript, 0xa40)), f_q))
mstore(add(transcript, 0x54a0), mulmod(mload(add(transcript, 0xa40)), 1, f_q))
mstore(add(transcript, 0x54c0), addmod(mload(add(transcript, 0x17a0)), sub(f_q, mload(add(transcript, 0x54a0))), f_q))
mstore(add(transcript, 0x54e0), mulmod(mload(add(transcript, 0xa40)), 4443263508319656594054352481848447997537391617204595126809744742387004492585, f_q))
mstore(add(transcript, 0x5500), addmod(mload(add(transcript, 0x17a0)), sub(f_q, mload(add(transcript, 0x54e0))), f_q))
mstore(add(transcript, 0x5520), mulmod(mload(add(transcript, 0xa40)), 11402394834529375719535454173347509224290498423785625657829583372803806900475, f_q))
mstore(add(transcript, 0x5540), addmod(mload(add(transcript, 0x17a0)), sub(f_q, mload(add(transcript, 0x5520))), f_q))
mstore(add(transcript, 0x5560), mulmod(mload(add(transcript, 0xa40)), 12491230264321380165669116208790466830459716800431293091713220204712467607643, f_q))
mstore(add(transcript, 0x5580), addmod(mload(add(transcript, 0x17a0)), sub(f_q, mload(add(transcript, 0x5560))), f_q))
mstore(add(transcript, 0x55a0), mulmod(mload(add(transcript, 0xa40)), 21180393220728113421338195116216869725258066600961496947533653125588029756005, f_q))
mstore(add(transcript, 0x55c0), addmod(mload(add(transcript, 0x17a0)), sub(f_q, mload(add(transcript, 0x55a0))), f_q))
mstore(add(transcript, 0x55e0), mulmod(mload(add(transcript, 0xa40)), 21846745818185811051373434299876022191132089169516983080959277716660228899818, f_q))
mstore(add(transcript, 0x5600), addmod(mload(add(transcript, 0x17a0)), sub(f_q, mload(add(transcript, 0x55e0))), f_q))
{            let result := mulmod(mload(add(transcript, 0x17a0)), 8066282055787475901673420555035560535710817593291328670948830103998216087188, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 13821960816051799320572985190221714552837546807124705672749374082577592408429, f_q), result, f_q)mstore(add(transcript, 0x5620), result)        }
{            let result := mulmod(mload(add(transcript, 0x17a0)), 19968324678227145013248315861515595301245912644541587902686803196084490696647, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 2652279421035414460371318391121293595959370598409287323185787737283079651270, f_q), result, f_q)mstore(add(transcript, 0x5640), result)        }
{            let result := mulmod(mload(add(transcript, 0x17a0)), 2652279421035414460371318391121293595959370598409287323185787737283079651270, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 19367074469347227157046979956364450920724362242668588573146737185273452907601, f_q), result, f_q)mstore(add(transcript, 0x5660), result)        }
{            let result := mulmod(mload(add(transcript, 0x17a0)), 5728955065969648051880489897163235636379640954457863903141118671545973649876, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 11131803335553698406238999414095177806538558655198059953539642575164592088996, f_q), result, f_q)mstore(add(transcript, 0x5680), result)        }
mstore(add(transcript, 0x56a0), mulmod(1, mload(add(transcript, 0x54c0)), f_q))
mstore(add(transcript, 0x56c0), mulmod(mload(add(transcript, 0x56a0)), mload(add(transcript, 0x5600)), f_q))
mstore(add(transcript, 0x56e0), mulmod(mload(add(transcript, 0x56c0)), mload(add(transcript, 0x5500)), f_q))
mstore(add(transcript, 0x5700), mulmod(mload(add(transcript, 0x56e0)), mload(add(transcript, 0x5580)), f_q))
{            let result := mulmod(mload(add(transcript, 0x17a0)), 41497053653464170872971445381252897416275230899051262738926469915579595800, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 21846745818185811051373434299876022191132089169516983080959277716660228899817, f_q), result, f_q)mstore(add(transcript, 0x5720), result)        }
{            let result := mulmod(mload(add(transcript, 0x17a0)), 21846745818185811051373434299876022191132089169516983080959277716660228899817, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 17403482309866154457319081818027574193594697552312387954149532974273224407233, f_q), result, f_q)mstore(add(transcript, 0x5740), result)        }
{            let result := mulmod(mload(add(transcript, 0x17a0)), 1, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q), result, f_q)mstore(add(transcript, 0x5760), result)        }
{            let result := mulmod(mload(add(transcript, 0x17a0)), 10485848037309899502710951571909765864257865976630408685868620813772001595143, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 11402394834529375719535454173347509224290498423785625657829583372803806900474, f_q), result, f_q)mstore(add(transcript, 0x5780), result)        }
{            let result := mulmod(mload(add(transcript, 0x17a0)), 11402394834529375719535454173347509224290498423785625657829583372803806900474, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 5545166320312543757176643718986770037302882363778492581314708552725780098827, f_q), result, f_q)mstore(add(transcript, 0x57a0), result)        }
mstore(add(transcript, 0x57c0), mulmod(mload(add(transcript, 0x56a0)), mload(add(transcript, 0x5540)), f_q))
{            let result := mulmod(mload(add(transcript, 0x17a0)), 19550482963636032496507824053356571186980560079138601892369352376314767105176, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 2337759908203242725738581691900703901567804321277432451328851810261041390441, f_q), result, f_q)mstore(add(transcript, 0x57e0), result)        }
{            let result := mulmod(mload(add(transcript, 0x17a0)), 6864017523829827661538877064511657693937746400280130103616449492479205074625, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 8176406603941074973579828757454043030101025654304527229739395789558437229636, f_q), result, f_q)mstore(add(transcript, 0x5800), result)        }
{            let result := mulmod(mload(add(transcript, 0x17a0)), 1208363231502528720962640213919841679473696796176395546734070070553011066292, f_q)result := addmod(mulmod(mload(add(transcript, 0xa40)), 13927816816077446377946003702584403455282257763096126200719395408961442331222, f_q), result, f_q)mstore(add(transcript, 0x5820), result)        }
mstore(add(transcript, 0x5840), mulmod(mload(add(transcript, 0x56c0)), mload(add(transcript, 0x55c0)), f_q))
{            let prod := mload(add(transcript, 0x5620))                prod := mulmod(mload(add(transcript, 0x5640)), prod, f_q)                mstore(add(transcript, 0x5860), prod)                            prod := mulmod(mload(add(transcript, 0x5660)), prod, f_q)                mstore(add(transcript, 0x5880), prod)                            prod := mulmod(mload(add(transcript, 0x5680)), prod, f_q)                mstore(add(transcript, 0x58a0), prod)                            prod := mulmod(mload(add(transcript, 0x5720)), prod, f_q)                mstore(add(transcript, 0x58c0), prod)                            prod := mulmod(mload(add(transcript, 0x5740)), prod, f_q)                mstore(add(transcript, 0x58e0), prod)                            prod := mulmod(mload(add(transcript, 0x56c0)), prod, f_q)                mstore(add(transcript, 0x5900), prod)                            prod := mulmod(mload(add(transcript, 0x5760)), prod, f_q)                mstore(add(transcript, 0x5920), prod)                            prod := mulmod(mload(add(transcript, 0x56a0)), prod, f_q)                mstore(add(transcript, 0x5940), prod)                            prod := mulmod(mload(add(transcript, 0x5780)), prod, f_q)                mstore(add(transcript, 0x5960), prod)                            prod := mulmod(mload(add(transcript, 0x57a0)), prod, f_q)                mstore(add(transcript, 0x5980), prod)                            prod := mulmod(mload(add(transcript, 0x57c0)), prod, f_q)                mstore(add(transcript, 0x59a0), prod)                            prod := mulmod(mload(add(transcript, 0x57e0)), prod, f_q)                mstore(add(transcript, 0x59c0), prod)                            prod := mulmod(mload(add(transcript, 0x5800)), prod, f_q)                mstore(add(transcript, 0x59e0), prod)                            prod := mulmod(mload(add(transcript, 0x5820)), prod, f_q)                mstore(add(transcript, 0x5a00), prod)                            prod := mulmod(mload(add(transcript, 0x5840)), prod, f_q)                mstore(add(transcript, 0x5a20), prod)                    }
mstore(add(transcript, 0x5a60), 32)
mstore(add(transcript, 0x5a80), 32)
mstore(add(transcript, 0x5aa0), 32)
mstore(add(transcript, 0x5ac0), mload(add(transcript, 0x5a20)))
mstore(add(transcript, 0x5ae0), 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(add(transcript, 0x5b00), 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, add(transcript, 0x5a60), 0xc0, add(transcript, 0x5a40), 0x20), 1), success)
{                        let inv := mload(add(transcript, 0x5a40))            let v                            v := mload(add(transcript, 0x5840))                    mstore(add(transcript, 0x5840), mulmod(mload(add(transcript, 0x5a00)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5820))                    mstore(add(transcript, 0x5820), mulmod(mload(add(transcript, 0x59e0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5800))                    mstore(add(transcript, 0x5800), mulmod(mload(add(transcript, 0x59c0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x57e0))                    mstore(add(transcript, 0x57e0), mulmod(mload(add(transcript, 0x59a0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x57c0))                    mstore(add(transcript, 0x57c0), mulmod(mload(add(transcript, 0x5980)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x57a0))                    mstore(add(transcript, 0x57a0), mulmod(mload(add(transcript, 0x5960)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5780))                    mstore(add(transcript, 0x5780), mulmod(mload(add(transcript, 0x5940)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x56a0))                    mstore(add(transcript, 0x56a0), mulmod(mload(add(transcript, 0x5920)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5760))                    mstore(add(transcript, 0x5760), mulmod(mload(add(transcript, 0x5900)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x56c0))                    mstore(add(transcript, 0x56c0), mulmod(mload(add(transcript, 0x58e0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5740))                    mstore(add(transcript, 0x5740), mulmod(mload(add(transcript, 0x58c0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5720))                    mstore(add(transcript, 0x5720), mulmod(mload(add(transcript, 0x58a0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5680))                    mstore(add(transcript, 0x5680), mulmod(mload(add(transcript, 0x5880)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5660))                    mstore(add(transcript, 0x5660), mulmod(mload(add(transcript, 0x5860)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5640))                    mstore(add(transcript, 0x5640), mulmod(mload(add(transcript, 0x5620)), inv, f_q))                    inv := mulmod(v, inv, f_q)                mstore(add(transcript, 0x5620), inv)        }
{            let result := mload(add(transcript, 0x5620))result := addmod(mload(add(transcript, 0x5640)), result, f_q)result := addmod(mload(add(transcript, 0x5660)), result, f_q)result := addmod(mload(add(transcript, 0x5680)), result, f_q)mstore(add(transcript, 0x5b20), result)        }
mstore(add(transcript, 0x5b40), mulmod(mload(add(transcript, 0x5700)), mload(add(transcript, 0x56c0)), f_q))
{            let result := mload(add(transcript, 0x5720))result := addmod(mload(add(transcript, 0x5740)), result, f_q)mstore(add(transcript, 0x5b60), result)        }
mstore(add(transcript, 0x5b80), mulmod(mload(add(transcript, 0x5700)), mload(add(transcript, 0x56a0)), f_q))
{            let result := mload(add(transcript, 0x5760))mstore(add(transcript, 0x5ba0), result)        }
mstore(add(transcript, 0x5bc0), mulmod(mload(add(transcript, 0x5700)), mload(add(transcript, 0x57c0)), f_q))
{            let result := mload(add(transcript, 0x5780))result := addmod(mload(add(transcript, 0x57a0)), result, f_q)mstore(add(transcript, 0x5be0), result)        }
mstore(add(transcript, 0x5c00), mulmod(mload(add(transcript, 0x5700)), mload(add(transcript, 0x5840)), f_q))
{            let result := mload(add(transcript, 0x57e0))result := addmod(mload(add(transcript, 0x5800)), result, f_q)result := addmod(mload(add(transcript, 0x5820)), result, f_q)mstore(add(transcript, 0x5c20), result)        }
{            let prod := mload(add(transcript, 0x5b20))                prod := mulmod(mload(add(transcript, 0x5b60)), prod, f_q)                mstore(add(transcript, 0x5c40), prod)                            prod := mulmod(mload(add(transcript, 0x5ba0)), prod, f_q)                mstore(add(transcript, 0x5c60), prod)                            prod := mulmod(mload(add(transcript, 0x5be0)), prod, f_q)                mstore(add(transcript, 0x5c80), prod)                            prod := mulmod(mload(add(transcript, 0x5c20)), prod, f_q)                mstore(add(transcript, 0x5ca0), prod)                    }
mstore(add(transcript, 0x5ce0), 32)
mstore(add(transcript, 0x5d00), 32)
mstore(add(transcript, 0x5d20), 32)
mstore(add(transcript, 0x5d40), mload(add(transcript, 0x5ca0)))
mstore(add(transcript, 0x5d60), 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(add(transcript, 0x5d80), 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, add(transcript, 0x5ce0), 0xc0, add(transcript, 0x5cc0), 0x20), 1), success)
{                        let inv := mload(add(transcript, 0x5cc0))            let v                            v := mload(add(transcript, 0x5c20))                    mstore(add(transcript, 0x5c20), mulmod(mload(add(transcript, 0x5c80)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5be0))                    mstore(add(transcript, 0x5be0), mulmod(mload(add(transcript, 0x5c60)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5ba0))                    mstore(add(transcript, 0x5ba0), mulmod(mload(add(transcript, 0x5c40)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x5b60))                    mstore(add(transcript, 0x5b60), mulmod(mload(add(transcript, 0x5b20)), inv, f_q))                    inv := mulmod(v, inv, f_q)                mstore(add(transcript, 0x5b20), inv)        }
mstore(add(transcript, 0x5da0), mulmod(mload(add(transcript, 0x5b40)), mload(add(transcript, 0x5b60)), f_q))
mstore(add(transcript, 0x5dc0), mulmod(mload(add(transcript, 0x5b80)), mload(add(transcript, 0x5ba0)), f_q))
mstore(add(transcript, 0x5de0), mulmod(mload(add(transcript, 0x5bc0)), mload(add(transcript, 0x5be0)), f_q))
mstore(add(transcript, 0x5e00), mulmod(mload(add(transcript, 0x5c00)), mload(add(transcript, 0x5c20)), f_q))
mstore(add(transcript, 0x5e20), mulmod(mload(add(transcript, 0x16a0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5e40), mulmod(mload(add(transcript, 0x5e20)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5e60), mulmod(mload(add(transcript, 0x5e40)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5e80), mulmod(mload(add(transcript, 0x5e60)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5ea0), mulmod(mload(add(transcript, 0x5e80)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5ec0), mulmod(mload(add(transcript, 0x5ea0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5ee0), mulmod(mload(add(transcript, 0x5ec0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5f00), mulmod(mload(add(transcript, 0x5ee0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5f20), mulmod(mload(add(transcript, 0x5f00)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5f40), mulmod(mload(add(transcript, 0x5f20)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5f60), mulmod(mload(add(transcript, 0x5f40)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5f80), mulmod(mload(add(transcript, 0x5f60)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5fa0), mulmod(mload(add(transcript, 0x5f80)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5fc0), mulmod(mload(add(transcript, 0x5fa0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x5fe0), mulmod(mload(add(transcript, 0x5fc0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6000), mulmod(mload(add(transcript, 0x5fe0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6020), mulmod(mload(add(transcript, 0x6000)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6040), mulmod(mload(add(transcript, 0x6020)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6060), mulmod(mload(add(transcript, 0x6040)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6080), mulmod(mload(add(transcript, 0x6060)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x60a0), mulmod(mload(add(transcript, 0x6080)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x60c0), mulmod(mload(add(transcript, 0x60a0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x60e0), mulmod(mload(add(transcript, 0x60c0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6100), mulmod(mload(add(transcript, 0x60e0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6120), mulmod(mload(add(transcript, 0x6100)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6140), mulmod(mload(add(transcript, 0x6120)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6160), mulmod(mload(add(transcript, 0x6140)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6180), mulmod(mload(add(transcript, 0x6160)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x61a0), mulmod(mload(add(transcript, 0x6180)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x61c0), mulmod(mload(add(transcript, 0x61a0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x61e0), mulmod(mload(add(transcript, 0x61c0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6200), mulmod(mload(add(transcript, 0x61e0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6220), mulmod(mload(add(transcript, 0x6200)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6240), mulmod(mload(add(transcript, 0x6220)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6260), mulmod(mload(add(transcript, 0x6240)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6280), mulmod(mload(add(transcript, 0x1700)), mload(add(transcript, 0x1700)), f_q))
mstore(add(transcript, 0x62a0), mulmod(mload(add(transcript, 0x6280)), mload(add(transcript, 0x1700)), f_q))
mstore(add(transcript, 0x62c0), mulmod(mload(add(transcript, 0x62a0)), mload(add(transcript, 0x1700)), f_q))
mstore(add(transcript, 0x62e0), mulmod(mload(add(transcript, 0x62c0)), mload(add(transcript, 0x1700)), f_q))
{            let result := mulmod(mload(add(transcript, 0xa80)), mload(add(transcript, 0x5620)), f_q)result := addmod(mulmod(mload(add(transcript, 0xaa0)), mload(add(transcript, 0x5640)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xac0)), mload(add(transcript, 0x5660)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xae0)), mload(add(transcript, 0x5680)), f_q), result, f_q)mstore(add(transcript, 0x6300), result)        }
mstore(add(transcript, 0x6320), mulmod(mload(add(transcript, 0x6300)), mload(add(transcript, 0x5b20)), f_q))
mstore(add(transcript, 0x6340), mulmod(sub(f_q, mload(add(transcript, 0x6320))), 1, f_q))
{            let result := mulmod(mload(add(transcript, 0xb00)), mload(add(transcript, 0x5620)), f_q)result := addmod(mulmod(mload(add(transcript, 0xb20)), mload(add(transcript, 0x5640)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xb40)), mload(add(transcript, 0x5660)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xb60)), mload(add(transcript, 0x5680)), f_q), result, f_q)mstore(add(transcript, 0x6360), result)        }
mstore(add(transcript, 0x6380), mulmod(mload(add(transcript, 0x6360)), mload(add(transcript, 0x5b20)), f_q))
mstore(add(transcript, 0x63a0), mulmod(sub(f_q, mload(add(transcript, 0x6380))), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x63c0), mulmod(1, mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x63e0), addmod(mload(add(transcript, 0x6340)), mload(add(transcript, 0x63a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0xb80)), mload(add(transcript, 0x5620)), f_q)result := addmod(mulmod(mload(add(transcript, 0xba0)), mload(add(transcript, 0x5640)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xbc0)), mload(add(transcript, 0x5660)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xbe0)), mload(add(transcript, 0x5680)), f_q), result, f_q)mstore(add(transcript, 0x6400), result)        }
mstore(add(transcript, 0x6420), mulmod(mload(add(transcript, 0x6400)), mload(add(transcript, 0x5b20)), f_q))
mstore(add(transcript, 0x6440), mulmod(sub(f_q, mload(add(transcript, 0x6420))), mload(add(transcript, 0x5e20)), f_q))
mstore(add(transcript, 0x6460), mulmod(1, mload(add(transcript, 0x5e20)), f_q))
mstore(add(transcript, 0x6480), addmod(mload(add(transcript, 0x63e0)), mload(add(transcript, 0x6440)), f_q))
{            let result := mulmod(mload(add(transcript, 0xc00)), mload(add(transcript, 0x5620)), f_q)result := addmod(mulmod(mload(add(transcript, 0xc20)), mload(add(transcript, 0x5640)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xc40)), mload(add(transcript, 0x5660)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xc60)), mload(add(transcript, 0x5680)), f_q), result, f_q)mstore(add(transcript, 0x64a0), result)        }
mstore(add(transcript, 0x64c0), mulmod(mload(add(transcript, 0x64a0)), mload(add(transcript, 0x5b20)), f_q))
mstore(add(transcript, 0x64e0), mulmod(sub(f_q, mload(add(transcript, 0x64c0))), mload(add(transcript, 0x5e40)), f_q))
mstore(add(transcript, 0x6500), mulmod(1, mload(add(transcript, 0x5e40)), f_q))
mstore(add(transcript, 0x6520), addmod(mload(add(transcript, 0x6480)), mload(add(transcript, 0x64e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0xc80)), mload(add(transcript, 0x5620)), f_q)result := addmod(mulmod(mload(add(transcript, 0xca0)), mload(add(transcript, 0x5640)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xcc0)), mload(add(transcript, 0x5660)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xce0)), mload(add(transcript, 0x5680)), f_q), result, f_q)mstore(add(transcript, 0x6540), result)        }
mstore(add(transcript, 0x6560), mulmod(mload(add(transcript, 0x6540)), mload(add(transcript, 0x5b20)), f_q))
mstore(add(transcript, 0x6580), mulmod(sub(f_q, mload(add(transcript, 0x6560))), mload(add(transcript, 0x5e60)), f_q))
mstore(add(transcript, 0x65a0), mulmod(1, mload(add(transcript, 0x5e60)), f_q))
mstore(add(transcript, 0x65c0), addmod(mload(add(transcript, 0x6520)), mload(add(transcript, 0x6580)), f_q))
{            let result := mulmod(mload(add(transcript, 0xd00)), mload(add(transcript, 0x5620)), f_q)result := addmod(mulmod(mload(add(transcript, 0xd20)), mload(add(transcript, 0x5640)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xd40)), mload(add(transcript, 0x5660)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xd60)), mload(add(transcript, 0x5680)), f_q), result, f_q)mstore(add(transcript, 0x65e0), result)        }
mstore(add(transcript, 0x6600), mulmod(mload(add(transcript, 0x65e0)), mload(add(transcript, 0x5b20)), f_q))
mstore(add(transcript, 0x6620), mulmod(sub(f_q, mload(add(transcript, 0x6600))), mload(add(transcript, 0x5e80)), f_q))
mstore(add(transcript, 0x6640), mulmod(1, mload(add(transcript, 0x5e80)), f_q))
mstore(add(transcript, 0x6660), addmod(mload(add(transcript, 0x65c0)), mload(add(transcript, 0x6620)), f_q))
{            let result := mulmod(mload(add(transcript, 0xd80)), mload(add(transcript, 0x5620)), f_q)result := addmod(mulmod(mload(add(transcript, 0xda0)), mload(add(transcript, 0x5640)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xdc0)), mload(add(transcript, 0x5660)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xde0)), mload(add(transcript, 0x5680)), f_q), result, f_q)mstore(add(transcript, 0x6680), result)        }
mstore(add(transcript, 0x66a0), mulmod(mload(add(transcript, 0x6680)), mload(add(transcript, 0x5b20)), f_q))
mstore(add(transcript, 0x66c0), mulmod(sub(f_q, mload(add(transcript, 0x66a0))), mload(add(transcript, 0x5ea0)), f_q))
mstore(add(transcript, 0x66e0), mulmod(1, mload(add(transcript, 0x5ea0)), f_q))
mstore(add(transcript, 0x6700), addmod(mload(add(transcript, 0x6660)), mload(add(transcript, 0x66c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0xe00)), mload(add(transcript, 0x5620)), f_q)result := addmod(mulmod(mload(add(transcript, 0xe20)), mload(add(transcript, 0x5640)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xe40)), mload(add(transcript, 0x5660)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0xe60)), mload(add(transcript, 0x5680)), f_q), result, f_q)mstore(add(transcript, 0x6720), result)        }
mstore(add(transcript, 0x6740), mulmod(mload(add(transcript, 0x6720)), mload(add(transcript, 0x5b20)), f_q))
mstore(add(transcript, 0x6760), mulmod(sub(f_q, mload(add(transcript, 0x6740))), mload(add(transcript, 0x5ec0)), f_q))
mstore(add(transcript, 0x6780), mulmod(1, mload(add(transcript, 0x5ec0)), f_q))
mstore(add(transcript, 0x67a0), addmod(mload(add(transcript, 0x6700)), mload(add(transcript, 0x6760)), f_q))
mstore(add(transcript, 0x67c0), mulmod(mload(add(transcript, 0x67a0)), 1, f_q))
mstore(add(transcript, 0x67e0), mulmod(mload(add(transcript, 0x63c0)), 1, f_q))
mstore(add(transcript, 0x6800), mulmod(mload(add(transcript, 0x6460)), 1, f_q))
mstore(add(transcript, 0x6820), mulmod(mload(add(transcript, 0x6500)), 1, f_q))
mstore(add(transcript, 0x6840), mulmod(mload(add(transcript, 0x65a0)), 1, f_q))
mstore(add(transcript, 0x6860), mulmod(mload(add(transcript, 0x6640)), 1, f_q))
mstore(add(transcript, 0x6880), mulmod(mload(add(transcript, 0x66e0)), 1, f_q))
mstore(add(transcript, 0x68a0), mulmod(mload(add(transcript, 0x6780)), 1, f_q))
mstore(add(transcript, 0x68c0), mulmod(1, mload(add(transcript, 0x5b40)), f_q))
{            let result := mulmod(mload(add(transcript, 0xe80)), mload(add(transcript, 0x5720)), f_q)result := addmod(mulmod(mload(add(transcript, 0xf60)), mload(add(transcript, 0x5740)), f_q), result, f_q)mstore(add(transcript, 0x68e0), result)        }
mstore(add(transcript, 0x6900), mulmod(mload(add(transcript, 0x68e0)), mload(add(transcript, 0x5da0)), f_q))
mstore(add(transcript, 0x6920), mulmod(sub(f_q, mload(add(transcript, 0x6900))), 1, f_q))
mstore(add(transcript, 0x6940), mulmod(mload(add(transcript, 0x68c0)), 1, f_q))
{            let result := mulmod(mload(add(transcript, 0xee0)), mload(add(transcript, 0x5720)), f_q)result := addmod(mulmod(mload(add(transcript, 0xf80)), mload(add(transcript, 0x5740)), f_q), result, f_q)mstore(add(transcript, 0x6960), result)        }
mstore(add(transcript, 0x6980), mulmod(mload(add(transcript, 0x6960)), mload(add(transcript, 0x5da0)), f_q))
mstore(add(transcript, 0x69a0), mulmod(sub(f_q, mload(add(transcript, 0x6980))), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x69c0), mulmod(mload(add(transcript, 0x68c0)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x69e0), addmod(mload(add(transcript, 0x6920)), mload(add(transcript, 0x69a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1460)), mload(add(transcript, 0x5720)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1480)), mload(add(transcript, 0x5740)), f_q), result, f_q)mstore(add(transcript, 0x6a00), result)        }
mstore(add(transcript, 0x6a20), mulmod(mload(add(transcript, 0x6a00)), mload(add(transcript, 0x5da0)), f_q))
mstore(add(transcript, 0x6a40), mulmod(sub(f_q, mload(add(transcript, 0x6a20))), mload(add(transcript, 0x5e20)), f_q))
mstore(add(transcript, 0x6a60), mulmod(mload(add(transcript, 0x68c0)), mload(add(transcript, 0x5e20)), f_q))
mstore(add(transcript, 0x6a80), addmod(mload(add(transcript, 0x69e0)), mload(add(transcript, 0x6a40)), f_q))
{            let result := mulmod(mload(add(transcript, 0x14a0)), mload(add(transcript, 0x5720)), f_q)result := addmod(mulmod(mload(add(transcript, 0x14c0)), mload(add(transcript, 0x5740)), f_q), result, f_q)mstore(add(transcript, 0x6aa0), result)        }
mstore(add(transcript, 0x6ac0), mulmod(mload(add(transcript, 0x6aa0)), mload(add(transcript, 0x5da0)), f_q))
mstore(add(transcript, 0x6ae0), mulmod(sub(f_q, mload(add(transcript, 0x6ac0))), mload(add(transcript, 0x5e40)), f_q))
mstore(add(transcript, 0x6b00), mulmod(mload(add(transcript, 0x68c0)), mload(add(transcript, 0x5e40)), f_q))
mstore(add(transcript, 0x6b20), addmod(mload(add(transcript, 0x6a80)), mload(add(transcript, 0x6ae0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1540)), mload(add(transcript, 0x5720)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1560)), mload(add(transcript, 0x5740)), f_q), result, f_q)mstore(add(transcript, 0x6b40), result)        }
mstore(add(transcript, 0x6b60), mulmod(mload(add(transcript, 0x6b40)), mload(add(transcript, 0x5da0)), f_q))
mstore(add(transcript, 0x6b80), mulmod(sub(f_q, mload(add(transcript, 0x6b60))), mload(add(transcript, 0x5e60)), f_q))
mstore(add(transcript, 0x6ba0), mulmod(mload(add(transcript, 0x68c0)), mload(add(transcript, 0x5e60)), f_q))
mstore(add(transcript, 0x6bc0), addmod(mload(add(transcript, 0x6b20)), mload(add(transcript, 0x6b80)), f_q))
{            let result := mulmod(mload(add(transcript, 0x15e0)), mload(add(transcript, 0x5720)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1600)), mload(add(transcript, 0x5740)), f_q), result, f_q)mstore(add(transcript, 0x6be0), result)        }
mstore(add(transcript, 0x6c00), mulmod(mload(add(transcript, 0x6be0)), mload(add(transcript, 0x5da0)), f_q))
mstore(add(transcript, 0x6c20), mulmod(sub(f_q, mload(add(transcript, 0x6c00))), mload(add(transcript, 0x5e80)), f_q))
mstore(add(transcript, 0x6c40), mulmod(mload(add(transcript, 0x68c0)), mload(add(transcript, 0x5e80)), f_q))
mstore(add(transcript, 0x6c60), addmod(mload(add(transcript, 0x6bc0)), mload(add(transcript, 0x6c20)), f_q))
mstore(add(transcript, 0x6c80), mulmod(mload(add(transcript, 0x6c60)), mload(add(transcript, 0x1700)), f_q))
mstore(add(transcript, 0x6ca0), mulmod(mload(add(transcript, 0x6940)), mload(add(transcript, 0x1700)), f_q))
mstore(add(transcript, 0x6cc0), mulmod(mload(add(transcript, 0x69c0)), mload(add(transcript, 0x1700)), f_q))
mstore(add(transcript, 0x6ce0), mulmod(mload(add(transcript, 0x6a60)), mload(add(transcript, 0x1700)), f_q))
mstore(add(transcript, 0x6d00), mulmod(mload(add(transcript, 0x6b00)), mload(add(transcript, 0x1700)), f_q))
mstore(add(transcript, 0x6d20), mulmod(mload(add(transcript, 0x6ba0)), mload(add(transcript, 0x1700)), f_q))
mstore(add(transcript, 0x6d40), mulmod(mload(add(transcript, 0x6c40)), mload(add(transcript, 0x1700)), f_q))
mstore(add(transcript, 0x6d60), addmod(mload(add(transcript, 0x67c0)), mload(add(transcript, 0x6c80)), f_q))
mstore(add(transcript, 0x6d80), mulmod(1, mload(add(transcript, 0x5b80)), f_q))
{            let result := mulmod(mload(add(transcript, 0xea0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x6da0), result)        }
mstore(add(transcript, 0x6dc0), mulmod(mload(add(transcript, 0x6da0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x6de0), mulmod(sub(f_q, mload(add(transcript, 0x6dc0))), 1, f_q))
mstore(add(transcript, 0x6e00), mulmod(mload(add(transcript, 0x6d80)), 1, f_q))
{            let result := mulmod(mload(add(transcript, 0xec0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x6e20), result)        }
mstore(add(transcript, 0x6e40), mulmod(mload(add(transcript, 0x6e20)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x6e60), mulmod(sub(f_q, mload(add(transcript, 0x6e40))), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6e80), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x6ea0), addmod(mload(add(transcript, 0x6de0)), mload(add(transcript, 0x6e60)), f_q))
{            let result := mulmod(mload(add(transcript, 0xf00)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x6ec0), result)        }
mstore(add(transcript, 0x6ee0), mulmod(mload(add(transcript, 0x6ec0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x6f00), mulmod(sub(f_q, mload(add(transcript, 0x6ee0))), mload(add(transcript, 0x5e20)), f_q))
mstore(add(transcript, 0x6f20), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5e20)), f_q))
mstore(add(transcript, 0x6f40), addmod(mload(add(transcript, 0x6ea0)), mload(add(transcript, 0x6f00)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1520)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x6f60), result)        }
mstore(add(transcript, 0x6f80), mulmod(mload(add(transcript, 0x6f60)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x6fa0), mulmod(sub(f_q, mload(add(transcript, 0x6f80))), mload(add(transcript, 0x5e40)), f_q))
mstore(add(transcript, 0x6fc0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5e40)), f_q))
mstore(add(transcript, 0x6fe0), addmod(mload(add(transcript, 0x6f40)), mload(add(transcript, 0x6fa0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x15c0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7000), result)        }
mstore(add(transcript, 0x7020), mulmod(mload(add(transcript, 0x7000)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7040), mulmod(sub(f_q, mload(add(transcript, 0x7020))), mload(add(transcript, 0x5e60)), f_q))
mstore(add(transcript, 0x7060), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5e60)), f_q))
mstore(add(transcript, 0x7080), addmod(mload(add(transcript, 0x6fe0)), mload(add(transcript, 0x7040)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1660)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x70a0), result)        }
mstore(add(transcript, 0x70c0), mulmod(mload(add(transcript, 0x70a0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x70e0), mulmod(sub(f_q, mload(add(transcript, 0x70c0))), mload(add(transcript, 0x5e80)), f_q))
mstore(add(transcript, 0x7100), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5e80)), f_q))
mstore(add(transcript, 0x7120), addmod(mload(add(transcript, 0x7080)), mload(add(transcript, 0x70e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0xfa0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7140), result)        }
mstore(add(transcript, 0x7160), mulmod(mload(add(transcript, 0x7140)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7180), mulmod(sub(f_q, mload(add(transcript, 0x7160))), mload(add(transcript, 0x5ea0)), f_q))
mstore(add(transcript, 0x71a0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5ea0)), f_q))
mstore(add(transcript, 0x71c0), addmod(mload(add(transcript, 0x7120)), mload(add(transcript, 0x7180)), f_q))
{            let result := mulmod(mload(add(transcript, 0xfc0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x71e0), result)        }
mstore(add(transcript, 0x7200), mulmod(mload(add(transcript, 0x71e0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7220), mulmod(sub(f_q, mload(add(transcript, 0x7200))), mload(add(transcript, 0x5ec0)), f_q))
mstore(add(transcript, 0x7240), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5ec0)), f_q))
mstore(add(transcript, 0x7260), addmod(mload(add(transcript, 0x71c0)), mload(add(transcript, 0x7220)), f_q))
{            let result := mulmod(mload(add(transcript, 0xfe0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7280), result)        }
mstore(add(transcript, 0x72a0), mulmod(mload(add(transcript, 0x7280)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x72c0), mulmod(sub(f_q, mload(add(transcript, 0x72a0))), mload(add(transcript, 0x5ee0)), f_q))
mstore(add(transcript, 0x72e0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5ee0)), f_q))
mstore(add(transcript, 0x7300), addmod(mload(add(transcript, 0x7260)), mload(add(transcript, 0x72c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1000)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7320), result)        }
mstore(add(transcript, 0x7340), mulmod(mload(add(transcript, 0x7320)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7360), mulmod(sub(f_q, mload(add(transcript, 0x7340))), mload(add(transcript, 0x5f00)), f_q))
mstore(add(transcript, 0x7380), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5f00)), f_q))
mstore(add(transcript, 0x73a0), addmod(mload(add(transcript, 0x7300)), mload(add(transcript, 0x7360)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1020)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x73c0), result)        }
mstore(add(transcript, 0x73e0), mulmod(mload(add(transcript, 0x73c0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7400), mulmod(sub(f_q, mload(add(transcript, 0x73e0))), mload(add(transcript, 0x5f20)), f_q))
mstore(add(transcript, 0x7420), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5f20)), f_q))
mstore(add(transcript, 0x7440), addmod(mload(add(transcript, 0x73a0)), mload(add(transcript, 0x7400)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1040)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7460), result)        }
mstore(add(transcript, 0x7480), mulmod(mload(add(transcript, 0x7460)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x74a0), mulmod(sub(f_q, mload(add(transcript, 0x7480))), mload(add(transcript, 0x5f40)), f_q))
mstore(add(transcript, 0x74c0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5f40)), f_q))
mstore(add(transcript, 0x74e0), addmod(mload(add(transcript, 0x7440)), mload(add(transcript, 0x74a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1060)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7500), result)        }
mstore(add(transcript, 0x7520), mulmod(mload(add(transcript, 0x7500)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7540), mulmod(sub(f_q, mload(add(transcript, 0x7520))), mload(add(transcript, 0x5f60)), f_q))
mstore(add(transcript, 0x7560), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5f60)), f_q))
mstore(add(transcript, 0x7580), addmod(mload(add(transcript, 0x74e0)), mload(add(transcript, 0x7540)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1080)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x75a0), result)        }
mstore(add(transcript, 0x75c0), mulmod(mload(add(transcript, 0x75a0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x75e0), mulmod(sub(f_q, mload(add(transcript, 0x75c0))), mload(add(transcript, 0x5f80)), f_q))
mstore(add(transcript, 0x7600), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5f80)), f_q))
mstore(add(transcript, 0x7620), addmod(mload(add(transcript, 0x7580)), mload(add(transcript, 0x75e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x10a0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7640), result)        }
mstore(add(transcript, 0x7660), mulmod(mload(add(transcript, 0x7640)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7680), mulmod(sub(f_q, mload(add(transcript, 0x7660))), mload(add(transcript, 0x5fa0)), f_q))
mstore(add(transcript, 0x76a0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5fa0)), f_q))
mstore(add(transcript, 0x76c0), addmod(mload(add(transcript, 0x7620)), mload(add(transcript, 0x7680)), f_q))
{            let result := mulmod(mload(add(transcript, 0x10c0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x76e0), result)        }
mstore(add(transcript, 0x7700), mulmod(mload(add(transcript, 0x76e0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7720), mulmod(sub(f_q, mload(add(transcript, 0x7700))), mload(add(transcript, 0x5fc0)), f_q))
mstore(add(transcript, 0x7740), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5fc0)), f_q))
mstore(add(transcript, 0x7760), addmod(mload(add(transcript, 0x76c0)), mload(add(transcript, 0x7720)), f_q))
{            let result := mulmod(mload(add(transcript, 0x10e0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7780), result)        }
mstore(add(transcript, 0x77a0), mulmod(mload(add(transcript, 0x7780)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x77c0), mulmod(sub(f_q, mload(add(transcript, 0x77a0))), mload(add(transcript, 0x5fe0)), f_q))
mstore(add(transcript, 0x77e0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x5fe0)), f_q))
mstore(add(transcript, 0x7800), addmod(mload(add(transcript, 0x7760)), mload(add(transcript, 0x77c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1100)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7820), result)        }
mstore(add(transcript, 0x7840), mulmod(mload(add(transcript, 0x7820)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7860), mulmod(sub(f_q, mload(add(transcript, 0x7840))), mload(add(transcript, 0x6000)), f_q))
mstore(add(transcript, 0x7880), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6000)), f_q))
mstore(add(transcript, 0x78a0), addmod(mload(add(transcript, 0x7800)), mload(add(transcript, 0x7860)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1140)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x78c0), result)        }
mstore(add(transcript, 0x78e0), mulmod(mload(add(transcript, 0x78c0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7900), mulmod(sub(f_q, mload(add(transcript, 0x78e0))), mload(add(transcript, 0x6020)), f_q))
mstore(add(transcript, 0x7920), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6020)), f_q))
mstore(add(transcript, 0x7940), addmod(mload(add(transcript, 0x78a0)), mload(add(transcript, 0x7900)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1160)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7960), result)        }
mstore(add(transcript, 0x7980), mulmod(mload(add(transcript, 0x7960)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x79a0), mulmod(sub(f_q, mload(add(transcript, 0x7980))), mload(add(transcript, 0x6040)), f_q))
mstore(add(transcript, 0x79c0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6040)), f_q))
mstore(add(transcript, 0x79e0), addmod(mload(add(transcript, 0x7940)), mload(add(transcript, 0x79a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1180)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7a00), result)        }
mstore(add(transcript, 0x7a20), mulmod(mload(add(transcript, 0x7a00)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7a40), mulmod(sub(f_q, mload(add(transcript, 0x7a20))), mload(add(transcript, 0x6060)), f_q))
mstore(add(transcript, 0x7a60), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6060)), f_q))
mstore(add(transcript, 0x7a80), addmod(mload(add(transcript, 0x79e0)), mload(add(transcript, 0x7a40)), f_q))
{            let result := mulmod(mload(add(transcript, 0x11a0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7aa0), result)        }
mstore(add(transcript, 0x7ac0), mulmod(mload(add(transcript, 0x7aa0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7ae0), mulmod(sub(f_q, mload(add(transcript, 0x7ac0))), mload(add(transcript, 0x6080)), f_q))
mstore(add(transcript, 0x7b00), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6080)), f_q))
mstore(add(transcript, 0x7b20), addmod(mload(add(transcript, 0x7a80)), mload(add(transcript, 0x7ae0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x11c0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7b40), result)        }
mstore(add(transcript, 0x7b60), mulmod(mload(add(transcript, 0x7b40)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7b80), mulmod(sub(f_q, mload(add(transcript, 0x7b60))), mload(add(transcript, 0x60a0)), f_q))
mstore(add(transcript, 0x7ba0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x60a0)), f_q))
mstore(add(transcript, 0x7bc0), addmod(mload(add(transcript, 0x7b20)), mload(add(transcript, 0x7b80)), f_q))
{            let result := mulmod(mload(add(transcript, 0x11e0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7be0), result)        }
mstore(add(transcript, 0x7c00), mulmod(mload(add(transcript, 0x7be0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7c20), mulmod(sub(f_q, mload(add(transcript, 0x7c00))), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x7c40), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x7c60), addmod(mload(add(transcript, 0x7bc0)), mload(add(transcript, 0x7c20)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1200)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7c80), result)        }
mstore(add(transcript, 0x7ca0), mulmod(mload(add(transcript, 0x7c80)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7cc0), mulmod(sub(f_q, mload(add(transcript, 0x7ca0))), mload(add(transcript, 0x60e0)), f_q))
mstore(add(transcript, 0x7ce0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x60e0)), f_q))
mstore(add(transcript, 0x7d00), addmod(mload(add(transcript, 0x7c60)), mload(add(transcript, 0x7cc0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1220)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7d20), result)        }
mstore(add(transcript, 0x7d40), mulmod(mload(add(transcript, 0x7d20)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7d60), mulmod(sub(f_q, mload(add(transcript, 0x7d40))), mload(add(transcript, 0x6100)), f_q))
mstore(add(transcript, 0x7d80), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6100)), f_q))
mstore(add(transcript, 0x7da0), addmod(mload(add(transcript, 0x7d00)), mload(add(transcript, 0x7d60)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1240)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7dc0), result)        }
mstore(add(transcript, 0x7de0), mulmod(mload(add(transcript, 0x7dc0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7e00), mulmod(sub(f_q, mload(add(transcript, 0x7de0))), mload(add(transcript, 0x6120)), f_q))
mstore(add(transcript, 0x7e20), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6120)), f_q))
mstore(add(transcript, 0x7e40), addmod(mload(add(transcript, 0x7da0)), mload(add(transcript, 0x7e00)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1260)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7e60), result)        }
mstore(add(transcript, 0x7e80), mulmod(mload(add(transcript, 0x7e60)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7ea0), mulmod(sub(f_q, mload(add(transcript, 0x7e80))), mload(add(transcript, 0x6140)), f_q))
mstore(add(transcript, 0x7ec0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6140)), f_q))
mstore(add(transcript, 0x7ee0), addmod(mload(add(transcript, 0x7e40)), mload(add(transcript, 0x7ea0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1280)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7f00), result)        }
mstore(add(transcript, 0x7f20), mulmod(mload(add(transcript, 0x7f00)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7f40), mulmod(sub(f_q, mload(add(transcript, 0x7f20))), mload(add(transcript, 0x6160)), f_q))
mstore(add(transcript, 0x7f60), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6160)), f_q))
mstore(add(transcript, 0x7f80), addmod(mload(add(transcript, 0x7ee0)), mload(add(transcript, 0x7f40)), f_q))
{            let result := mulmod(mload(add(transcript, 0x12a0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x7fa0), result)        }
mstore(add(transcript, 0x7fc0), mulmod(mload(add(transcript, 0x7fa0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x7fe0), mulmod(sub(f_q, mload(add(transcript, 0x7fc0))), mload(add(transcript, 0x6180)), f_q))
mstore(add(transcript, 0x8000), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6180)), f_q))
mstore(add(transcript, 0x8020), addmod(mload(add(transcript, 0x7f80)), mload(add(transcript, 0x7fe0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x12c0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x8040), result)        }
mstore(add(transcript, 0x8060), mulmod(mload(add(transcript, 0x8040)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x8080), mulmod(sub(f_q, mload(add(transcript, 0x8060))), mload(add(transcript, 0x61a0)), f_q))
mstore(add(transcript, 0x80a0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x61a0)), f_q))
mstore(add(transcript, 0x80c0), addmod(mload(add(transcript, 0x8020)), mload(add(transcript, 0x8080)), f_q))
{            let result := mulmod(mload(add(transcript, 0x12e0)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x80e0), result)        }
mstore(add(transcript, 0x8100), mulmod(mload(add(transcript, 0x80e0)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x8120), mulmod(sub(f_q, mload(add(transcript, 0x8100))), mload(add(transcript, 0x61c0)), f_q))
mstore(add(transcript, 0x8140), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x61c0)), f_q))
mstore(add(transcript, 0x8160), addmod(mload(add(transcript, 0x80c0)), mload(add(transcript, 0x8120)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1300)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x8180), result)        }
mstore(add(transcript, 0x81a0), mulmod(mload(add(transcript, 0x8180)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x81c0), mulmod(sub(f_q, mload(add(transcript, 0x81a0))), mload(add(transcript, 0x61e0)), f_q))
mstore(add(transcript, 0x81e0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x61e0)), f_q))
mstore(add(transcript, 0x8200), addmod(mload(add(transcript, 0x8160)), mload(add(transcript, 0x81c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1320)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x8220), result)        }
mstore(add(transcript, 0x8240), mulmod(mload(add(transcript, 0x8220)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x8260), mulmod(sub(f_q, mload(add(transcript, 0x8240))), mload(add(transcript, 0x6200)), f_q))
mstore(add(transcript, 0x8280), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6200)), f_q))
mstore(add(transcript, 0x82a0), addmod(mload(add(transcript, 0x8200)), mload(add(transcript, 0x8260)), f_q))
mstore(add(transcript, 0x82c0), mulmod(mload(add(transcript, 0x53e0)), mload(add(transcript, 0x5b80)), f_q))
mstore(add(transcript, 0x82e0), mulmod(mload(add(transcript, 0x5400)), mload(add(transcript, 0x5b80)), f_q))
mstore(add(transcript, 0x8300), mulmod(mload(add(transcript, 0x5420)), mload(add(transcript, 0x5b80)), f_q))
mstore(add(transcript, 0x8320), mulmod(mload(add(transcript, 0x5440)), mload(add(transcript, 0x5b80)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5460)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x8340), result)        }
mstore(add(transcript, 0x8360), mulmod(mload(add(transcript, 0x8340)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x8380), mulmod(sub(f_q, mload(add(transcript, 0x8360))), mload(add(transcript, 0x6220)), f_q))
mstore(add(transcript, 0x83a0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6220)), f_q))
mstore(add(transcript, 0x83c0), mulmod(mload(add(transcript, 0x82c0)), mload(add(transcript, 0x6220)), f_q))
mstore(add(transcript, 0x83e0), mulmod(mload(add(transcript, 0x82e0)), mload(add(transcript, 0x6220)), f_q))
mstore(add(transcript, 0x8400), mulmod(mload(add(transcript, 0x8300)), mload(add(transcript, 0x6220)), f_q))
mstore(add(transcript, 0x8420), mulmod(mload(add(transcript, 0x8320)), mload(add(transcript, 0x6220)), f_q))
mstore(add(transcript, 0x8440), addmod(mload(add(transcript, 0x82a0)), mload(add(transcript, 0x8380)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1120)), mload(add(transcript, 0x5760)), f_q)mstore(add(transcript, 0x8460), result)        }
mstore(add(transcript, 0x8480), mulmod(mload(add(transcript, 0x8460)), mload(add(transcript, 0x5dc0)), f_q))
mstore(add(transcript, 0x84a0), mulmod(sub(f_q, mload(add(transcript, 0x8480))), mload(add(transcript, 0x6240)), f_q))
mstore(add(transcript, 0x84c0), mulmod(mload(add(transcript, 0x6d80)), mload(add(transcript, 0x6240)), f_q))
mstore(add(transcript, 0x84e0), addmod(mload(add(transcript, 0x8440)), mload(add(transcript, 0x84a0)), f_q))
mstore(add(transcript, 0x8500), mulmod(mload(add(transcript, 0x84e0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8520), mulmod(mload(add(transcript, 0x6e00)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8540), mulmod(mload(add(transcript, 0x6e80)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8560), mulmod(mload(add(transcript, 0x6f20)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8580), mulmod(mload(add(transcript, 0x6fc0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x85a0), mulmod(mload(add(transcript, 0x7060)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x85c0), mulmod(mload(add(transcript, 0x7100)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x85e0), mulmod(mload(add(transcript, 0x71a0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8600), mulmod(mload(add(transcript, 0x7240)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8620), mulmod(mload(add(transcript, 0x72e0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8640), mulmod(mload(add(transcript, 0x7380)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8660), mulmod(mload(add(transcript, 0x7420)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8680), mulmod(mload(add(transcript, 0x74c0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x86a0), mulmod(mload(add(transcript, 0x7560)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x86c0), mulmod(mload(add(transcript, 0x7600)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x86e0), mulmod(mload(add(transcript, 0x76a0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8700), mulmod(mload(add(transcript, 0x7740)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8720), mulmod(mload(add(transcript, 0x77e0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8740), mulmod(mload(add(transcript, 0x7880)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8760), mulmod(mload(add(transcript, 0x7920)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8780), mulmod(mload(add(transcript, 0x79c0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x87a0), mulmod(mload(add(transcript, 0x7a60)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x87c0), mulmod(mload(add(transcript, 0x7b00)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x87e0), mulmod(mload(add(transcript, 0x7ba0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8800), mulmod(mload(add(transcript, 0x7c40)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8820), mulmod(mload(add(transcript, 0x7ce0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8840), mulmod(mload(add(transcript, 0x7d80)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8860), mulmod(mload(add(transcript, 0x7e20)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8880), mulmod(mload(add(transcript, 0x7ec0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x88a0), mulmod(mload(add(transcript, 0x7f60)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x88c0), mulmod(mload(add(transcript, 0x8000)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x88e0), mulmod(mload(add(transcript, 0x80a0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8900), mulmod(mload(add(transcript, 0x8140)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8920), mulmod(mload(add(transcript, 0x81e0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8940), mulmod(mload(add(transcript, 0x8280)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8960), mulmod(mload(add(transcript, 0x83a0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8980), mulmod(mload(add(transcript, 0x83c0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x89a0), mulmod(mload(add(transcript, 0x83e0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x89c0), mulmod(mload(add(transcript, 0x8400)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x89e0), mulmod(mload(add(transcript, 0x8420)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8a00), mulmod(mload(add(transcript, 0x84c0)), mload(add(transcript, 0x6280)), f_q))
mstore(add(transcript, 0x8a20), addmod(mload(add(transcript, 0x6d60)), mload(add(transcript, 0x8500)), f_q))
mstore(add(transcript, 0x8a40), mulmod(1, mload(add(transcript, 0x5bc0)), f_q))
{            let result := mulmod(mload(add(transcript, 0xf20)), mload(add(transcript, 0x5780)), f_q)result := addmod(mulmod(mload(add(transcript, 0xf40)), mload(add(transcript, 0x57a0)), f_q), result, f_q)mstore(add(transcript, 0x8a60), result)        }
mstore(add(transcript, 0x8a80), mulmod(mload(add(transcript, 0x8a60)), mload(add(transcript, 0x5de0)), f_q))
mstore(add(transcript, 0x8aa0), mulmod(sub(f_q, mload(add(transcript, 0x8a80))), 1, f_q))
mstore(add(transcript, 0x8ac0), mulmod(mload(add(transcript, 0x8a40)), 1, f_q))
{            let result := mulmod(mload(add(transcript, 0x14e0)), mload(add(transcript, 0x5780)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1500)), mload(add(transcript, 0x57a0)), f_q), result, f_q)mstore(add(transcript, 0x8ae0), result)        }
mstore(add(transcript, 0x8b00), mulmod(mload(add(transcript, 0x8ae0)), mload(add(transcript, 0x5de0)), f_q))
mstore(add(transcript, 0x8b20), mulmod(sub(f_q, mload(add(transcript, 0x8b00))), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x8b40), mulmod(mload(add(transcript, 0x8a40)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x8b60), addmod(mload(add(transcript, 0x8aa0)), mload(add(transcript, 0x8b20)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1580)), mload(add(transcript, 0x5780)), f_q)result := addmod(mulmod(mload(add(transcript, 0x15a0)), mload(add(transcript, 0x57a0)), f_q), result, f_q)mstore(add(transcript, 0x8b80), result)        }
mstore(add(transcript, 0x8ba0), mulmod(mload(add(transcript, 0x8b80)), mload(add(transcript, 0x5de0)), f_q))
mstore(add(transcript, 0x8bc0), mulmod(sub(f_q, mload(add(transcript, 0x8ba0))), mload(add(transcript, 0x5e20)), f_q))
mstore(add(transcript, 0x8be0), mulmod(mload(add(transcript, 0x8a40)), mload(add(transcript, 0x5e20)), f_q))
mstore(add(transcript, 0x8c00), addmod(mload(add(transcript, 0x8b60)), mload(add(transcript, 0x8bc0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1620)), mload(add(transcript, 0x5780)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1640)), mload(add(transcript, 0x57a0)), f_q), result, f_q)mstore(add(transcript, 0x8c20), result)        }
mstore(add(transcript, 0x8c40), mulmod(mload(add(transcript, 0x8c20)), mload(add(transcript, 0x5de0)), f_q))
mstore(add(transcript, 0x8c60), mulmod(sub(f_q, mload(add(transcript, 0x8c40))), mload(add(transcript, 0x5e40)), f_q))
mstore(add(transcript, 0x8c80), mulmod(mload(add(transcript, 0x8a40)), mload(add(transcript, 0x5e40)), f_q))
mstore(add(transcript, 0x8ca0), addmod(mload(add(transcript, 0x8c00)), mload(add(transcript, 0x8c60)), f_q))
mstore(add(transcript, 0x8cc0), mulmod(mload(add(transcript, 0x8ca0)), mload(add(transcript, 0x62a0)), f_q))
mstore(add(transcript, 0x8ce0), mulmod(mload(add(transcript, 0x8ac0)), mload(add(transcript, 0x62a0)), f_q))
mstore(add(transcript, 0x8d00), mulmod(mload(add(transcript, 0x8b40)), mload(add(transcript, 0x62a0)), f_q))
mstore(add(transcript, 0x8d20), mulmod(mload(add(transcript, 0x8be0)), mload(add(transcript, 0x62a0)), f_q))
mstore(add(transcript, 0x8d40), mulmod(mload(add(transcript, 0x8c80)), mload(add(transcript, 0x62a0)), f_q))
mstore(add(transcript, 0x8d60), addmod(mload(add(transcript, 0x8a20)), mload(add(transcript, 0x8cc0)), f_q))
mstore(add(transcript, 0x8d80), mulmod(1, mload(add(transcript, 0x5c00)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1340)), mload(add(transcript, 0x57e0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1360)), mload(add(transcript, 0x5800)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1380)), mload(add(transcript, 0x5820)), f_q), result, f_q)mstore(add(transcript, 0x8da0), result)        }
mstore(add(transcript, 0x8dc0), mulmod(mload(add(transcript, 0x8da0)), mload(add(transcript, 0x5e00)), f_q))
mstore(add(transcript, 0x8de0), mulmod(sub(f_q, mload(add(transcript, 0x8dc0))), 1, f_q))
mstore(add(transcript, 0x8e00), mulmod(mload(add(transcript, 0x8d80)), 1, f_q))
{            let result := mulmod(mload(add(transcript, 0x13a0)), mload(add(transcript, 0x57e0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x13c0)), mload(add(transcript, 0x5800)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x13e0)), mload(add(transcript, 0x5820)), f_q), result, f_q)mstore(add(transcript, 0x8e20), result)        }
mstore(add(transcript, 0x8e40), mulmod(mload(add(transcript, 0x8e20)), mload(add(transcript, 0x5e00)), f_q))
mstore(add(transcript, 0x8e60), mulmod(sub(f_q, mload(add(transcript, 0x8e40))), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x8e80), mulmod(mload(add(transcript, 0x8d80)), mload(add(transcript, 0x16a0)), f_q))
mstore(add(transcript, 0x8ea0), addmod(mload(add(transcript, 0x8de0)), mload(add(transcript, 0x8e60)), f_q))
{            let result := mulmod(mload(add(transcript, 0x1400)), mload(add(transcript, 0x57e0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x1420)), mload(add(transcript, 0x5800)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x1440)), mload(add(transcript, 0x5820)), f_q), result, f_q)mstore(add(transcript, 0x8ec0), result)        }
mstore(add(transcript, 0x8ee0), mulmod(mload(add(transcript, 0x8ec0)), mload(add(transcript, 0x5e00)), f_q))
mstore(add(transcript, 0x8f00), mulmod(sub(f_q, mload(add(transcript, 0x8ee0))), mload(add(transcript, 0x5e20)), f_q))
mstore(add(transcript, 0x8f20), mulmod(mload(add(transcript, 0x8d80)), mload(add(transcript, 0x5e20)), f_q))
mstore(add(transcript, 0x8f40), addmod(mload(add(transcript, 0x8ea0)), mload(add(transcript, 0x8f00)), f_q))
mstore(add(transcript, 0x8f60), mulmod(mload(add(transcript, 0x8f40)), mload(add(transcript, 0x62c0)), f_q))
mstore(add(transcript, 0x8f80), mulmod(mload(add(transcript, 0x8e00)), mload(add(transcript, 0x62c0)), f_q))
mstore(add(transcript, 0x8fa0), mulmod(mload(add(transcript, 0x8e80)), mload(add(transcript, 0x62c0)), f_q))

        }}
        // transcriptBytes = abi.encode(transcript.length, transcript);
        bytes32[] memory newTranscript = new bytes32[](_transcript.length);
        for(uint i=0; i<_transcript.length; i++) {
            newTranscript[i] = transcript[i];
        }
        return (success, newTranscript);
    } 
}
