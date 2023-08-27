// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierFuncAbst.sol";

contract VerifierFunc3 is VerifierFuncAbst {
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
    mstore(add(transcript, 0x15500), addmod(mload(add(transcript, 0x154e0)), sub(f_q, mload(add(transcript, 0x6000))), f_q))
mstore(add(transcript, 0x15520), mulmod(mload(add(transcript, 0x15500)), mload(add(transcript, 0x6940)), f_q))
mstore(add(transcript, 0x15540), addmod(mload(add(transcript, 0x154c0)), mload(add(transcript, 0x15520)), f_q))
mstore(add(transcript, 0x15560), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x15540)), f_q))
mstore(add(transcript, 0x15580), addmod(mload(add(transcript, 0x6040)), mload(add(transcript, 0x1bc0)), f_q))
mstore(add(transcript, 0x155a0), mulmod(mload(add(transcript, 0x15580)), mload(add(transcript, 0x6020)), f_q))
mstore(add(transcript, 0x155c0), addmod(mload(add(transcript, 0x6080)), mload(add(transcript, 0x1c20)), f_q))
mstore(add(transcript, 0x155e0), mulmod(mload(add(transcript, 0x155c0)), mload(add(transcript, 0x155a0)), f_q))
mstore(add(transcript, 0x15600), mulmod(mload(add(transcript, 0x38a0)), mload(add(transcript, 0x40e0)), f_q))
mstore(add(transcript, 0x15620), addmod(mload(add(transcript, 0x15600)), mload(add(transcript, 0x13520)), f_q))
mstore(add(transcript, 0x15640), mulmod(mload(add(transcript, 0xf60)), mload(add(transcript, 0x15620)), f_q))
mstore(add(transcript, 0x15660), addmod(mload(add(transcript, 0x15640)), mload(add(transcript, 0x141e0)), f_q))
mstore(add(transcript, 0x15680), mulmod(mload(add(transcript, 0xf60)), mload(add(transcript, 0x15660)), f_q))
mstore(add(transcript, 0x156a0), addmod(mload(add(transcript, 0x15680)), mload(add(transcript, 0x14640)), f_q))
mstore(add(transcript, 0x156c0), mulmod(mload(add(transcript, 0xf60)), mload(add(transcript, 0x156a0)), f_q))
mstore(add(transcript, 0x156e0), addmod(mload(add(transcript, 0x156c0)), mload(add(transcript, 0x146c0)), f_q))
mstore(add(transcript, 0x15700), mulmod(mload(add(transcript, 0xf60)), mload(add(transcript, 0x156e0)), f_q))
mstore(add(transcript, 0x15720), addmod(mload(add(transcript, 0x15700)), mload(add(transcript, 0x14740)), f_q))
mstore(add(transcript, 0x15740), addmod(mload(add(transcript, 0x15720)), mload(add(transcript, 0x1bc0)), f_q))
mstore(add(transcript, 0x15760), mulmod(mload(add(transcript, 0x15740)), mload(add(transcript, 0x6000)), f_q))
mstore(add(transcript, 0x15780), mulmod(mload(add(transcript, 0x14da0)), mload(add(transcript, 0x15760)), f_q))
mstore(add(transcript, 0x157a0), addmod(mload(add(transcript, 0x155e0)), sub(f_q, mload(add(transcript, 0x15780))), f_q))
mstore(add(transcript, 0x157c0), mulmod(mload(add(transcript, 0x157a0)), mload(add(transcript, 0x8760)), f_q))
mstore(add(transcript, 0x157e0), addmod(mload(add(transcript, 0x15560)), mload(add(transcript, 0x157c0)), f_q))
mstore(add(transcript, 0x15800), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x157e0)), f_q))
mstore(add(transcript, 0x15820), addmod(mload(add(transcript, 0x6040)), sub(f_q, mload(add(transcript, 0x6080))), f_q))
mstore(add(transcript, 0x15840), mulmod(mload(add(transcript, 0x15820)), mload(add(transcript, 0x6a20)), f_q))
mstore(add(transcript, 0x15860), addmod(mload(add(transcript, 0x15800)), mload(add(transcript, 0x15840)), f_q))
mstore(add(transcript, 0x15880), mulmod(mload(add(transcript, 0x2700)), mload(add(transcript, 0x15860)), f_q))
mstore(add(transcript, 0x158a0), mulmod(mload(add(transcript, 0x15820)), mload(add(transcript, 0x8760)), f_q))
mstore(add(transcript, 0x158c0), addmod(mload(add(transcript, 0x6040)), sub(f_q, mload(add(transcript, 0x6060))), f_q))
mstore(add(transcript, 0x158e0), mulmod(mload(add(transcript, 0x158c0)), mload(add(transcript, 0x158a0)), f_q))
mstore(add(transcript, 0x15900), addmod(mload(add(transcript, 0x15880)), mload(add(transcript, 0x158e0)), f_q))
mstore(add(transcript, 0x15920), mulmod(mload(add(transcript, 0x6440)), mload(add(transcript, 0x6440)), f_q))
mstore(add(transcript, 0x15940), mulmod(mload(add(transcript, 0x15920)), mload(add(transcript, 0x6440)), f_q))
mstore(add(transcript, 0x15960), mulmod(mload(add(transcript, 0x15940)), mload(add(transcript, 0x6440)), f_q))
mstore(add(transcript, 0x15980), mulmod(mload(add(transcript, 0x15960)), mload(add(transcript, 0x6440)), f_q))
mstore(add(transcript, 0x159a0), mulmod(1, mload(add(transcript, 0x6440)), f_q))
mstore(add(transcript, 0x159c0), mulmod(1, mload(add(transcript, 0x15920)), f_q))
mstore(add(transcript, 0x159e0), mulmod(1, mload(add(transcript, 0x15940)), f_q))
mstore(add(transcript, 0x15a00), mulmod(1, mload(add(transcript, 0x15960)), f_q))
mstore(add(transcript, 0x15a20), mulmod(mload(add(transcript, 0x15900)), mload(add(transcript, 0x6460)), f_q))
mstore(add(transcript, 0x15a40), mulmod(mload(add(transcript, 0x6240)), mload(add(transcript, 0x28a0)), f_q))
mstore(add(transcript, 0x15a60), mulmod(mload(add(transcript, 0x28a0)), 1, f_q))
mstore(add(transcript, 0x15a80), addmod(mload(add(transcript, 0x61c0)), sub(f_q, mload(add(transcript, 0x15a60))), f_q))
mstore(add(transcript, 0x15aa0), mulmod(mload(add(transcript, 0x28a0)), 4443263508319656594054352481848447997537391617204595126809744742387004492585, f_q))
mstore(add(transcript, 0x15ac0), addmod(mload(add(transcript, 0x61c0)), sub(f_q, mload(add(transcript, 0x15aa0))), f_q))
mstore(add(transcript, 0x15ae0), mulmod(mload(add(transcript, 0x28a0)), 11402394834529375719535454173347509224290498423785625657829583372803806900475, f_q))
mstore(add(transcript, 0x15b00), addmod(mload(add(transcript, 0x61c0)), sub(f_q, mload(add(transcript, 0x15ae0))), f_q))
mstore(add(transcript, 0x15b20), mulmod(mload(add(transcript, 0x28a0)), 12491230264321380165669116208790466830459716800431293091713220204712467607643, f_q))
mstore(add(transcript, 0x15b40), addmod(mload(add(transcript, 0x61c0)), sub(f_q, mload(add(transcript, 0x15b20))), f_q))
mstore(add(transcript, 0x15b60), mulmod(mload(add(transcript, 0x28a0)), 21180393220728113421338195116216869725258066600961496947533653125588029756005, f_q))
mstore(add(transcript, 0x15b80), addmod(mload(add(transcript, 0x61c0)), sub(f_q, mload(add(transcript, 0x15b60))), f_q))
mstore(add(transcript, 0x15ba0), mulmod(mload(add(transcript, 0x28a0)), 21846745818185811051373434299876022191132089169516983080959277716660228899818, f_q))
mstore(add(transcript, 0x15bc0), addmod(mload(add(transcript, 0x61c0)), sub(f_q, mload(add(transcript, 0x15ba0))), f_q))
{            let result := mulmod(mload(add(transcript, 0x61c0)), 8066282055787475901673420555035560535710817593291328670948830103998216087188, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 13821960816051799320572985190221714552837546807124705672749374082577592408429, f_q), result, f_q)mstore(add(transcript, 0x15be0), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 19968324678227145013248315861515595301245912644541587902686803196084490696647, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 2652279421035414460371318391121293595959370598409287323185787737283079651270, f_q), result, f_q)mstore(add(transcript, 0x15c00), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 2652279421035414460371318391121293595959370598409287323185787737283079651270, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 19367074469347227157046979956364450920724362242668588573146737185273452907601, f_q), result, f_q)mstore(add(transcript, 0x15c20), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 5728955065969648051880489897163235636379640954457863903141118671545973649876, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 11131803335553698406238999414095177806538558655198059953539642575164592088996, f_q), result, f_q)mstore(add(transcript, 0x15c40), result)        }
mstore(add(transcript, 0x15c60), mulmod(1, mload(add(transcript, 0x15a80)), f_q))
mstore(add(transcript, 0x15c80), mulmod(mload(add(transcript, 0x15c60)), mload(add(transcript, 0x15bc0)), f_q))
mstore(add(transcript, 0x15ca0), mulmod(mload(add(transcript, 0x15c80)), mload(add(transcript, 0x15ac0)), f_q))
mstore(add(transcript, 0x15cc0), mulmod(mload(add(transcript, 0x15ca0)), mload(add(transcript, 0x15b40)), f_q))
{            let result := mulmod(mload(add(transcript, 0x61c0)), 1, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q), result, f_q)mstore(add(transcript, 0x15ce0), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 41497053653464170872971445381252897416275230899051262738926469915579595800, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 21846745818185811051373434299876022191132089169516983080959277716660228899817, f_q), result, f_q)mstore(add(transcript, 0x15d00), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 21846745818185811051373434299876022191132089169516983080959277716660228899817, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 17403482309866154457319081818027574193594697552312387954149532974273224407233, f_q), result, f_q)mstore(add(transcript, 0x15d20), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 10485848037309899502710951571909765864257865976630408685868620813772001595143, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 11402394834529375719535454173347509224290498423785625657829583372803806900474, f_q), result, f_q)mstore(add(transcript, 0x15d40), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 11402394834529375719535454173347509224290498423785625657829583372803806900474, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 5545166320312543757176643718986770037302882363778492581314708552725780098827, f_q), result, f_q)mstore(add(transcript, 0x15d60), result)        }
mstore(add(transcript, 0x15d80), mulmod(mload(add(transcript, 0x15c60)), mload(add(transcript, 0x15b00)), f_q))
{            let result := mulmod(mload(add(transcript, 0x61c0)), 8089463809655187742487735172323271730338600414125749227642401932241042710858, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 13798779062184087479758670572934003358209763986290285116055802254334765784759, f_q), result, f_q)mstore(add(transcript, 0x15da0), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 18325036677810672415558965945544957150579706065292982768343399936552929468943, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 21020899465919496918297310822967668437198476376793158048829550737529314705058, f_q), result, f_q)mstore(add(transcript, 0x15dc0), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 2695862788108824502738344877422711286618770311500175280486150800976385236115, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 21865061117971563381432091127969563893920581579581613787004632358332981871947, f_q), result, f_q)mstore(add(transcript, 0x15de0), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 19550482963636032496507824053356571186980560079138601892369352376314767105176, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 2337759908203242725738581691900703901567804321277432451328851810261041390441, f_q), result, f_q)mstore(add(transcript, 0x15e00), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 6864017523829827661538877064511657693937746400280130103616449492479205074625, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 8176406603941074973579828757454043030101025654304527229739395789558437229636, f_q), result, f_q)mstore(add(transcript, 0x15e20), result)        }
{            let result := mulmod(mload(add(transcript, 0x61c0)), 1208363231502528720962640213919841679473696796176395546734070070553011066292, f_q)result := addmod(mulmod(mload(add(transcript, 0x28a0)), 13927816816077446377946003702584403455282257763096126200719395408961442331222, f_q), result, f_q)mstore(add(transcript, 0x15e40), result)        }
mstore(add(transcript, 0x15e60), mulmod(mload(add(transcript, 0x15c80)), mload(add(transcript, 0x15b80)), f_q))
{            let prod := mload(add(transcript, 0x15be0))                prod := mulmod(mload(add(transcript, 0x15c00)), prod, f_q)                mstore(add(transcript, 0x15e80), prod)                            prod := mulmod(mload(add(transcript, 0x15c20)), prod, f_q)                mstore(add(transcript, 0x15ea0), prod)                            prod := mulmod(mload(add(transcript, 0x15c40)), prod, f_q)                mstore(add(transcript, 0x15ec0), prod)                            prod := mulmod(mload(add(transcript, 0x15ce0)), prod, f_q)                mstore(add(transcript, 0x15ee0), prod)                            prod := mulmod(mload(add(transcript, 0x15c60)), prod, f_q)                mstore(add(transcript, 0x15f00), prod)                            prod := mulmod(mload(add(transcript, 0x15d00)), prod, f_q)                mstore(add(transcript, 0x15f20), prod)                            prod := mulmod(mload(add(transcript, 0x15d20)), prod, f_q)                mstore(add(transcript, 0x15f40), prod)                            prod := mulmod(mload(add(transcript, 0x15c80)), prod, f_q)                mstore(add(transcript, 0x15f60), prod)                            prod := mulmod(mload(add(transcript, 0x15d40)), prod, f_q)                mstore(add(transcript, 0x15f80), prod)                            prod := mulmod(mload(add(transcript, 0x15d60)), prod, f_q)                mstore(add(transcript, 0x15fa0), prod)                            prod := mulmod(mload(add(transcript, 0x15d80)), prod, f_q)                mstore(add(transcript, 0x15fc0), prod)                            prod := mulmod(mload(add(transcript, 0x15da0)), prod, f_q)                mstore(add(transcript, 0x15fe0), prod)                            prod := mulmod(mload(add(transcript, 0x15dc0)), prod, f_q)                mstore(add(transcript, 0x16000), prod)                            prod := mulmod(mload(add(transcript, 0x15de0)), prod, f_q)                mstore(add(transcript, 0x16020), prod)                            prod := mulmod(mload(add(transcript, 0x15ca0)), prod, f_q)                mstore(add(transcript, 0x16040), prod)                            prod := mulmod(mload(add(transcript, 0x15e00)), prod, f_q)                mstore(add(transcript, 0x16060), prod)                            prod := mulmod(mload(add(transcript, 0x15e20)), prod, f_q)                mstore(add(transcript, 0x16080), prod)                            prod := mulmod(mload(add(transcript, 0x15e40)), prod, f_q)                mstore(add(transcript, 0x160a0), prod)                            prod := mulmod(mload(add(transcript, 0x15e60)), prod, f_q)                mstore(add(transcript, 0x160c0), prod)                    }
mstore(add(transcript, 0x16100), 32)
mstore(add(transcript, 0x16120), 32)
mstore(add(transcript, 0x16140), 32)
mstore(add(transcript, 0x16160), mload(add(transcript, 0x160c0)))
mstore(add(transcript, 0x16180), 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(add(transcript, 0x161a0), 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, add(transcript, 0x16100), 0xc0, add(transcript, 0x160e0), 0x20), 1), success)
{                        let inv := mload(add(transcript, 0x160e0))            let v                            v := mload(add(transcript, 0x15e60))                    mstore(add(transcript, 0x15e60), mulmod(mload(add(transcript, 0x160a0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15e40))                    mstore(add(transcript, 0x15e40), mulmod(mload(add(transcript, 0x16080)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15e20))                    mstore(add(transcript, 0x15e20), mulmod(mload(add(transcript, 0x16060)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15e00))                    mstore(add(transcript, 0x15e00), mulmod(mload(add(transcript, 0x16040)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15ca0))                    mstore(add(transcript, 0x15ca0), mulmod(mload(add(transcript, 0x16020)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15de0))                    mstore(add(transcript, 0x15de0), mulmod(mload(add(transcript, 0x16000)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15dc0))                    mstore(add(transcript, 0x15dc0), mulmod(mload(add(transcript, 0x15fe0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15da0))                    mstore(add(transcript, 0x15da0), mulmod(mload(add(transcript, 0x15fc0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15d80))                    mstore(add(transcript, 0x15d80), mulmod(mload(add(transcript, 0x15fa0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15d60))                    mstore(add(transcript, 0x15d60), mulmod(mload(add(transcript, 0x15f80)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15d40))                    mstore(add(transcript, 0x15d40), mulmod(mload(add(transcript, 0x15f60)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15c80))                    mstore(add(transcript, 0x15c80), mulmod(mload(add(transcript, 0x15f40)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15d20))                    mstore(add(transcript, 0x15d20), mulmod(mload(add(transcript, 0x15f20)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15d00))                    mstore(add(transcript, 0x15d00), mulmod(mload(add(transcript, 0x15f00)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15c60))                    mstore(add(transcript, 0x15c60), mulmod(mload(add(transcript, 0x15ee0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15ce0))                    mstore(add(transcript, 0x15ce0), mulmod(mload(add(transcript, 0x15ec0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15c40))                    mstore(add(transcript, 0x15c40), mulmod(mload(add(transcript, 0x15ea0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15c20))                    mstore(add(transcript, 0x15c20), mulmod(mload(add(transcript, 0x15e80)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x15c00))                    mstore(add(transcript, 0x15c00), mulmod(mload(add(transcript, 0x15be0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                mstore(add(transcript, 0x15be0), inv)        }
{            let result := mload(add(transcript, 0x15be0))result := addmod(mload(add(transcript, 0x15c00)), result, f_q)result := addmod(mload(add(transcript, 0x15c20)), result, f_q)result := addmod(mload(add(transcript, 0x15c40)), result, f_q)mstore(add(transcript, 0x161c0), result)        }
mstore(add(transcript, 0x161e0), mulmod(mload(add(transcript, 0x15cc0)), mload(add(transcript, 0x15c60)), f_q))
{            let result := mload(add(transcript, 0x15ce0))mstore(add(transcript, 0x16200), result)        }
mstore(add(transcript, 0x16220), mulmod(mload(add(transcript, 0x15cc0)), mload(add(transcript, 0x15c80)), f_q))
{            let result := mload(add(transcript, 0x15d00))result := addmod(mload(add(transcript, 0x15d20)), result, f_q)mstore(add(transcript, 0x16240), result)        }
mstore(add(transcript, 0x16260), mulmod(mload(add(transcript, 0x15cc0)), mload(add(transcript, 0x15d80)), f_q))
{            let result := mload(add(transcript, 0x15d40))result := addmod(mload(add(transcript, 0x15d60)), result, f_q)mstore(add(transcript, 0x16280), result)        }
mstore(add(transcript, 0x162a0), mulmod(mload(add(transcript, 0x15cc0)), mload(add(transcript, 0x15ca0)), f_q))
{            let result := mload(add(transcript, 0x15da0))result := addmod(mload(add(transcript, 0x15dc0)), result, f_q)result := addmod(mload(add(transcript, 0x15de0)), result, f_q)mstore(add(transcript, 0x162c0), result)        }
mstore(add(transcript, 0x162e0), mulmod(mload(add(transcript, 0x15cc0)), mload(add(transcript, 0x15e60)), f_q))
{            let result := mload(add(transcript, 0x15e00))result := addmod(mload(add(transcript, 0x15e20)), result, f_q)result := addmod(mload(add(transcript, 0x15e40)), result, f_q)mstore(add(transcript, 0x16300), result)        }
{            let prod := mload(add(transcript, 0x161c0))                prod := mulmod(mload(add(transcript, 0x16200)), prod, f_q)                mstore(add(transcript, 0x16320), prod)                            prod := mulmod(mload(add(transcript, 0x16240)), prod, f_q)                mstore(add(transcript, 0x16340), prod)                            prod := mulmod(mload(add(transcript, 0x16280)), prod, f_q)                mstore(add(transcript, 0x16360), prod)                            prod := mulmod(mload(add(transcript, 0x162c0)), prod, f_q)                mstore(add(transcript, 0x16380), prod)                            prod := mulmod(mload(add(transcript, 0x16300)), prod, f_q)                mstore(add(transcript, 0x163a0), prod)                    }
mstore(add(transcript, 0x163e0), 32)
mstore(add(transcript, 0x16400), 32)
mstore(add(transcript, 0x16420), 32)
mstore(add(transcript, 0x16440), mload(add(transcript, 0x163a0)))
mstore(add(transcript, 0x16460), 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(add(transcript, 0x16480), 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, add(transcript, 0x163e0), 0xc0, add(transcript, 0x163c0), 0x20), 1), success)
{                        let inv := mload(add(transcript, 0x163c0))            let v                            v := mload(add(transcript, 0x16300))                    mstore(add(transcript, 0x16300), mulmod(mload(add(transcript, 0x16380)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x162c0))                    mstore(add(transcript, 0x162c0), mulmod(mload(add(transcript, 0x16360)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x16280))                    mstore(add(transcript, 0x16280), mulmod(mload(add(transcript, 0x16340)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x16240))                    mstore(add(transcript, 0x16240), mulmod(mload(add(transcript, 0x16320)), inv, f_q))                    inv := mulmod(v, inv, f_q)                                    v := mload(add(transcript, 0x16200))                    mstore(add(transcript, 0x16200), mulmod(mload(add(transcript, 0x161c0)), inv, f_q))                    inv := mulmod(v, inv, f_q)                mstore(add(transcript, 0x161c0), inv)        }
mstore(add(transcript, 0x164a0), mulmod(mload(add(transcript, 0x161e0)), mload(add(transcript, 0x16200)), f_q))
mstore(add(transcript, 0x164c0), mulmod(mload(add(transcript, 0x16220)), mload(add(transcript, 0x16240)), f_q))
mstore(add(transcript, 0x164e0), mulmod(mload(add(transcript, 0x16260)), mload(add(transcript, 0x16280)), f_q))
mstore(add(transcript, 0x16500), mulmod(mload(add(transcript, 0x162a0)), mload(add(transcript, 0x162c0)), f_q))
mstore(add(transcript, 0x16520), mulmod(mload(add(transcript, 0x162e0)), mload(add(transcript, 0x16300)), f_q))
mstore(add(transcript, 0x16540), mulmod(mload(add(transcript, 0x60c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16560), mulmod(mload(add(transcript, 0x16540)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16580), mulmod(mload(add(transcript, 0x16560)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x165a0), mulmod(mload(add(transcript, 0x16580)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x165c0), mulmod(mload(add(transcript, 0x165a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x165e0), mulmod(mload(add(transcript, 0x165c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16600), mulmod(mload(add(transcript, 0x165e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16620), mulmod(mload(add(transcript, 0x16600)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16640), mulmod(mload(add(transcript, 0x16620)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16660), mulmod(mload(add(transcript, 0x16640)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16680), mulmod(mload(add(transcript, 0x16660)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x166a0), mulmod(mload(add(transcript, 0x16680)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x166c0), mulmod(mload(add(transcript, 0x166a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x166e0), mulmod(mload(add(transcript, 0x166c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16700), mulmod(mload(add(transcript, 0x166e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16720), mulmod(mload(add(transcript, 0x16700)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16740), mulmod(mload(add(transcript, 0x16720)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16760), mulmod(mload(add(transcript, 0x16740)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16780), mulmod(mload(add(transcript, 0x16760)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x167a0), mulmod(mload(add(transcript, 0x16780)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x167c0), mulmod(mload(add(transcript, 0x167a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x167e0), mulmod(mload(add(transcript, 0x167c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16800), mulmod(mload(add(transcript, 0x167e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16820), mulmod(mload(add(transcript, 0x16800)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16840), mulmod(mload(add(transcript, 0x16820)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16860), mulmod(mload(add(transcript, 0x16840)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16880), mulmod(mload(add(transcript, 0x16860)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x168a0), mulmod(mload(add(transcript, 0x16880)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x168c0), mulmod(mload(add(transcript, 0x168a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x168e0), mulmod(mload(add(transcript, 0x168c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16900), mulmod(mload(add(transcript, 0x168e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16920), mulmod(mload(add(transcript, 0x16900)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16940), mulmod(mload(add(transcript, 0x16920)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16960), mulmod(mload(add(transcript, 0x16940)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16980), mulmod(mload(add(transcript, 0x16960)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x169a0), mulmod(mload(add(transcript, 0x16980)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x169c0), mulmod(mload(add(transcript, 0x169a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x169e0), mulmod(mload(add(transcript, 0x169c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16a00), mulmod(mload(add(transcript, 0x169e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16a20), mulmod(mload(add(transcript, 0x16a00)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16a40), mulmod(mload(add(transcript, 0x16a20)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16a60), mulmod(mload(add(transcript, 0x16a40)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16a80), mulmod(mload(add(transcript, 0x16a60)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16aa0), mulmod(mload(add(transcript, 0x16a80)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16ac0), mulmod(mload(add(transcript, 0x16aa0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16ae0), mulmod(mload(add(transcript, 0x16ac0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16b00), mulmod(mload(add(transcript, 0x16ae0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16b20), mulmod(mload(add(transcript, 0x16b00)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16b40), mulmod(mload(add(transcript, 0x16b20)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16b60), mulmod(mload(add(transcript, 0x16b40)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16b80), mulmod(mload(add(transcript, 0x16b60)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16ba0), mulmod(mload(add(transcript, 0x16b80)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16bc0), mulmod(mload(add(transcript, 0x16ba0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16be0), mulmod(mload(add(transcript, 0x16bc0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16c00), mulmod(mload(add(transcript, 0x16be0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16c20), mulmod(mload(add(transcript, 0x16c00)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16c40), mulmod(mload(add(transcript, 0x16c20)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16c60), mulmod(mload(add(transcript, 0x16c40)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16c80), mulmod(mload(add(transcript, 0x16c60)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16ca0), mulmod(mload(add(transcript, 0x16c80)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16cc0), mulmod(mload(add(transcript, 0x16ca0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16ce0), mulmod(mload(add(transcript, 0x16cc0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16d00), mulmod(mload(add(transcript, 0x16ce0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16d20), mulmod(mload(add(transcript, 0x16d00)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16d40), mulmod(mload(add(transcript, 0x16d20)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16d60), mulmod(mload(add(transcript, 0x16d40)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16d80), mulmod(mload(add(transcript, 0x16d60)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16da0), mulmod(mload(add(transcript, 0x16d80)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16dc0), mulmod(mload(add(transcript, 0x16da0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16de0), mulmod(mload(add(transcript, 0x16dc0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16e00), mulmod(mload(add(transcript, 0x16de0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16e20), mulmod(mload(add(transcript, 0x16e00)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16e40), mulmod(mload(add(transcript, 0x16e20)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16e60), mulmod(mload(add(transcript, 0x16e40)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16e80), mulmod(mload(add(transcript, 0x16e60)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16ea0), mulmod(mload(add(transcript, 0x16e80)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16ec0), mulmod(mload(add(transcript, 0x16ea0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16ee0), mulmod(mload(add(transcript, 0x16ec0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16f00), mulmod(mload(add(transcript, 0x16ee0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16f20), mulmod(mload(add(transcript, 0x16f00)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16f40), mulmod(mload(add(transcript, 0x16f20)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16f60), mulmod(mload(add(transcript, 0x16f40)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16f80), mulmod(mload(add(transcript, 0x16f60)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16fa0), mulmod(mload(add(transcript, 0x16f80)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16fc0), mulmod(mload(add(transcript, 0x16fa0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x16fe0), mulmod(mload(add(transcript, 0x16fc0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17000), mulmod(mload(add(transcript, 0x16fe0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17020), mulmod(mload(add(transcript, 0x17000)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17040), mulmod(mload(add(transcript, 0x17020)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17060), mulmod(mload(add(transcript, 0x17040)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17080), mulmod(mload(add(transcript, 0x17060)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x170a0), mulmod(mload(add(transcript, 0x17080)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x170c0), mulmod(mload(add(transcript, 0x170a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x170e0), mulmod(mload(add(transcript, 0x170c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17100), mulmod(mload(add(transcript, 0x170e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17120), mulmod(mload(add(transcript, 0x17100)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17140), mulmod(mload(add(transcript, 0x17120)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17160), mulmod(mload(add(transcript, 0x17140)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17180), mulmod(mload(add(transcript, 0x17160)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x171a0), mulmod(mload(add(transcript, 0x17180)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x171c0), mulmod(mload(add(transcript, 0x171a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x171e0), mulmod(mload(add(transcript, 0x171c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17200), mulmod(mload(add(transcript, 0x171e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17220), mulmod(mload(add(transcript, 0x17200)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17240), mulmod(mload(add(transcript, 0x17220)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17260), mulmod(mload(add(transcript, 0x17240)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17280), mulmod(mload(add(transcript, 0x17260)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x172a0), mulmod(mload(add(transcript, 0x17280)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x172c0), mulmod(mload(add(transcript, 0x172a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x172e0), mulmod(mload(add(transcript, 0x172c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17300), mulmod(mload(add(transcript, 0x172e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17320), mulmod(mload(add(transcript, 0x17300)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17340), mulmod(mload(add(transcript, 0x17320)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17360), mulmod(mload(add(transcript, 0x17340)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17380), mulmod(mload(add(transcript, 0x17360)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x173a0), mulmod(mload(add(transcript, 0x17380)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x173c0), mulmod(mload(add(transcript, 0x173a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x173e0), mulmod(mload(add(transcript, 0x173c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17400), mulmod(mload(add(transcript, 0x173e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17420), mulmod(mload(add(transcript, 0x17400)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17440), mulmod(mload(add(transcript, 0x17420)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17460), mulmod(mload(add(transcript, 0x17440)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17480), mulmod(mload(add(transcript, 0x17460)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x174a0), mulmod(mload(add(transcript, 0x17480)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x174c0), mulmod(mload(add(transcript, 0x174a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x174e0), mulmod(mload(add(transcript, 0x174c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17500), mulmod(mload(add(transcript, 0x174e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17520), mulmod(mload(add(transcript, 0x17500)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17540), mulmod(mload(add(transcript, 0x17520)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17560), mulmod(mload(add(transcript, 0x17540)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17580), mulmod(mload(add(transcript, 0x17560)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x175a0), mulmod(mload(add(transcript, 0x17580)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x175c0), mulmod(mload(add(transcript, 0x175a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x175e0), mulmod(mload(add(transcript, 0x175c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17600), mulmod(mload(add(transcript, 0x175e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17620), mulmod(mload(add(transcript, 0x17600)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17640), mulmod(mload(add(transcript, 0x17620)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17660), mulmod(mload(add(transcript, 0x17640)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17680), mulmod(mload(add(transcript, 0x17660)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x176a0), mulmod(mload(add(transcript, 0x17680)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x176c0), mulmod(mload(add(transcript, 0x176a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x176e0), mulmod(mload(add(transcript, 0x176c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17700), mulmod(mload(add(transcript, 0x176e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17720), mulmod(mload(add(transcript, 0x17700)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17740), mulmod(mload(add(transcript, 0x17720)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17760), mulmod(mload(add(transcript, 0x17740)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17780), mulmod(mload(add(transcript, 0x17760)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x177a0), mulmod(mload(add(transcript, 0x17780)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x177c0), mulmod(mload(add(transcript, 0x177a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x177e0), mulmod(mload(add(transcript, 0x177c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17800), mulmod(mload(add(transcript, 0x177e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17820), mulmod(mload(add(transcript, 0x17800)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17840), mulmod(mload(add(transcript, 0x17820)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17860), mulmod(mload(add(transcript, 0x17840)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17880), mulmod(mload(add(transcript, 0x17860)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x178a0), mulmod(mload(add(transcript, 0x17880)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x178c0), mulmod(mload(add(transcript, 0x178a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x178e0), mulmod(mload(add(transcript, 0x178c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17900), mulmod(mload(add(transcript, 0x178e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17920), mulmod(mload(add(transcript, 0x17900)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17940), mulmod(mload(add(transcript, 0x17920)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17960), mulmod(mload(add(transcript, 0x17940)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17980), mulmod(mload(add(transcript, 0x17960)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x179a0), mulmod(mload(add(transcript, 0x17980)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x179c0), mulmod(mload(add(transcript, 0x179a0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x179e0), mulmod(mload(add(transcript, 0x179c0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17a00), mulmod(mload(add(transcript, 0x179e0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17a20), mulmod(mload(add(transcript, 0x17a00)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17a40), mulmod(mload(add(transcript, 0x17a20)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17a60), mulmod(mload(add(transcript, 0x17a40)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17a80), mulmod(mload(add(transcript, 0x17a60)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17aa0), mulmod(mload(add(transcript, 0x17a80)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17ac0), mulmod(mload(add(transcript, 0x17aa0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17ae0), mulmod(mload(add(transcript, 0x17ac0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17b00), mulmod(mload(add(transcript, 0x17ae0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17b20), mulmod(mload(add(transcript, 0x17b00)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17b40), mulmod(mload(add(transcript, 0x17b20)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17b60), mulmod(mload(add(transcript, 0x17b40)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17b80), mulmod(mload(add(transcript, 0x17b60)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17ba0), mulmod(mload(add(transcript, 0x17b80)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17bc0), mulmod(mload(add(transcript, 0x17ba0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17be0), mulmod(mload(add(transcript, 0x17bc0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17c00), mulmod(mload(add(transcript, 0x17be0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17c20), mulmod(mload(add(transcript, 0x17c00)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17c40), mulmod(mload(add(transcript, 0x17c20)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17c60), mulmod(mload(add(transcript, 0x17c40)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17c80), mulmod(mload(add(transcript, 0x17c60)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17ca0), mulmod(mload(add(transcript, 0x17c80)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17cc0), mulmod(mload(add(transcript, 0x17ca0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17ce0), mulmod(mload(add(transcript, 0x17cc0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17d00), mulmod(mload(add(transcript, 0x17ce0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17d20), mulmod(mload(add(transcript, 0x17d00)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17d40), mulmod(mload(add(transcript, 0x17d20)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17d60), mulmod(mload(add(transcript, 0x17d40)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17d80), mulmod(mload(add(transcript, 0x17d60)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17da0), mulmod(mload(add(transcript, 0x17d80)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17dc0), mulmod(mload(add(transcript, 0x17da0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17de0), mulmod(mload(add(transcript, 0x17dc0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17e00), mulmod(mload(add(transcript, 0x17de0)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17e20), mulmod(mload(add(transcript, 0x17e00)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17e40), mulmod(mload(add(transcript, 0x17e20)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17e60), mulmod(mload(add(transcript, 0x6120)), mload(add(transcript, 0x6120)), f_q))
mstore(add(transcript, 0x17e80), mulmod(mload(add(transcript, 0x17e60)), mload(add(transcript, 0x6120)), f_q))
mstore(add(transcript, 0x17ea0), mulmod(mload(add(transcript, 0x17e80)), mload(add(transcript, 0x6120)), f_q))
mstore(add(transcript, 0x17ec0), mulmod(mload(add(transcript, 0x17ea0)), mload(add(transcript, 0x6120)), f_q))
mstore(add(transcript, 0x17ee0), mulmod(mload(add(transcript, 0x17ec0)), mload(add(transcript, 0x6120)), f_q))
{            let result := mulmod(mload(add(transcript, 0x28e0)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2900)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2920)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2940)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x17f00), result)        }
mstore(add(transcript, 0x17f20), mulmod(mload(add(transcript, 0x17f00)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x17f40), mulmod(sub(f_q, mload(add(transcript, 0x17f20))), 1, f_q))
{            let result := mulmod(mload(add(transcript, 0x2960)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2980)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x29a0)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x29c0)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x17f60), result)        }
mstore(add(transcript, 0x17f80), mulmod(mload(add(transcript, 0x17f60)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x17fa0), mulmod(sub(f_q, mload(add(transcript, 0x17f80))), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17fc0), mulmod(1, mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x17fe0), addmod(mload(add(transcript, 0x17f40)), mload(add(transcript, 0x17fa0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x29e0)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2a00)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2a20)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2a40)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x18000), result)        }
mstore(add(transcript, 0x18020), mulmod(mload(add(transcript, 0x18000)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x18040), mulmod(sub(f_q, mload(add(transcript, 0x18020))), mload(add(transcript, 0x16540)), f_q))
mstore(add(transcript, 0x18060), mulmod(1, mload(add(transcript, 0x16540)), f_q))
mstore(add(transcript, 0x18080), addmod(mload(add(transcript, 0x17fe0)), mload(add(transcript, 0x18040)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2a60)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2a80)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2aa0)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2ac0)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x180a0), result)        }
mstore(add(transcript, 0x180c0), mulmod(mload(add(transcript, 0x180a0)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x180e0), mulmod(sub(f_q, mload(add(transcript, 0x180c0))), mload(add(transcript, 0x16560)), f_q))
mstore(add(transcript, 0x18100), mulmod(1, mload(add(transcript, 0x16560)), f_q))
mstore(add(transcript, 0x18120), addmod(mload(add(transcript, 0x18080)), mload(add(transcript, 0x180e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2ae0)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2b00)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2b20)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2b40)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x18140), result)        }
mstore(add(transcript, 0x18160), mulmod(mload(add(transcript, 0x18140)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x18180), mulmod(sub(f_q, mload(add(transcript, 0x18160))), mload(add(transcript, 0x16580)), f_q))
mstore(add(transcript, 0x181a0), mulmod(1, mload(add(transcript, 0x16580)), f_q))
mstore(add(transcript, 0x181c0), addmod(mload(add(transcript, 0x18120)), mload(add(transcript, 0x18180)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2b60)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2b80)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2ba0)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2bc0)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x181e0), result)        }
mstore(add(transcript, 0x18200), mulmod(mload(add(transcript, 0x181e0)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x18220), mulmod(sub(f_q, mload(add(transcript, 0x18200))), mload(add(transcript, 0x165a0)), f_q))
mstore(add(transcript, 0x18240), mulmod(1, mload(add(transcript, 0x165a0)), f_q))
mstore(add(transcript, 0x18260), addmod(mload(add(transcript, 0x181c0)), mload(add(transcript, 0x18220)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2be0)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2c00)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2c20)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2c40)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x18280), result)        }
mstore(add(transcript, 0x182a0), mulmod(mload(add(transcript, 0x18280)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x182c0), mulmod(sub(f_q, mload(add(transcript, 0x182a0))), mload(add(transcript, 0x165c0)), f_q))
mstore(add(transcript, 0x182e0), mulmod(1, mload(add(transcript, 0x165c0)), f_q))
mstore(add(transcript, 0x18300), addmod(mload(add(transcript, 0x18260)), mload(add(transcript, 0x182c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2c60)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2c80)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2ca0)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2cc0)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x18320), result)        }
mstore(add(transcript, 0x18340), mulmod(mload(add(transcript, 0x18320)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x18360), mulmod(sub(f_q, mload(add(transcript, 0x18340))), mload(add(transcript, 0x165e0)), f_q))
mstore(add(transcript, 0x18380), mulmod(1, mload(add(transcript, 0x165e0)), f_q))
mstore(add(transcript, 0x183a0), addmod(mload(add(transcript, 0x18300)), mload(add(transcript, 0x18360)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2ce0)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2d00)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2d20)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2d40)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x183c0), result)        }
mstore(add(transcript, 0x183e0), mulmod(mload(add(transcript, 0x183c0)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x18400), mulmod(sub(f_q, mload(add(transcript, 0x183e0))), mload(add(transcript, 0x16600)), f_q))
mstore(add(transcript, 0x18420), mulmod(1, mload(add(transcript, 0x16600)), f_q))
mstore(add(transcript, 0x18440), addmod(mload(add(transcript, 0x183a0)), mload(add(transcript, 0x18400)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2d60)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2d80)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2da0)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2dc0)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x18460), result)        }
mstore(add(transcript, 0x18480), mulmod(mload(add(transcript, 0x18460)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x184a0), mulmod(sub(f_q, mload(add(transcript, 0x18480))), mload(add(transcript, 0x16620)), f_q))
mstore(add(transcript, 0x184c0), mulmod(1, mload(add(transcript, 0x16620)), f_q))
mstore(add(transcript, 0x184e0), addmod(mload(add(transcript, 0x18440)), mload(add(transcript, 0x184a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2de0)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2e00)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2e20)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2e40)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x18500), result)        }
mstore(add(transcript, 0x18520), mulmod(mload(add(transcript, 0x18500)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x18540), mulmod(sub(f_q, mload(add(transcript, 0x18520))), mload(add(transcript, 0x16640)), f_q))
mstore(add(transcript, 0x18560), mulmod(1, mload(add(transcript, 0x16640)), f_q))
mstore(add(transcript, 0x18580), addmod(mload(add(transcript, 0x184e0)), mload(add(transcript, 0x18540)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2e60)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2e80)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2ea0)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2ec0)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x185a0), result)        }
mstore(add(transcript, 0x185c0), mulmod(mload(add(transcript, 0x185a0)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x185e0), mulmod(sub(f_q, mload(add(transcript, 0x185c0))), mload(add(transcript, 0x16660)), f_q))
mstore(add(transcript, 0x18600), mulmod(1, mload(add(transcript, 0x16660)), f_q))
mstore(add(transcript, 0x18620), addmod(mload(add(transcript, 0x18580)), mload(add(transcript, 0x185e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2ee0)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2f00)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2f20)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2f40)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x18640), result)        }
mstore(add(transcript, 0x18660), mulmod(mload(add(transcript, 0x18640)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x18680), mulmod(sub(f_q, mload(add(transcript, 0x18660))), mload(add(transcript, 0x16680)), f_q))
mstore(add(transcript, 0x186a0), mulmod(1, mload(add(transcript, 0x16680)), f_q))
mstore(add(transcript, 0x186c0), addmod(mload(add(transcript, 0x18620)), mload(add(transcript, 0x18680)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2f60)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x2f80)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2fa0)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x2fc0)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x186e0), result)        }
mstore(add(transcript, 0x18700), mulmod(mload(add(transcript, 0x186e0)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x18720), mulmod(sub(f_q, mload(add(transcript, 0x18700))), mload(add(transcript, 0x166a0)), f_q))
mstore(add(transcript, 0x18740), mulmod(1, mload(add(transcript, 0x166a0)), f_q))
mstore(add(transcript, 0x18760), addmod(mload(add(transcript, 0x186c0)), mload(add(transcript, 0x18720)), f_q))
{            let result := mulmod(mload(add(transcript, 0x2fe0)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x3000)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x3020)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x3040)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x18780), result)        }
mstore(add(transcript, 0x187a0), mulmod(mload(add(transcript, 0x18780)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x187c0), mulmod(sub(f_q, mload(add(transcript, 0x187a0))), mload(add(transcript, 0x166c0)), f_q))
mstore(add(transcript, 0x187e0), mulmod(1, mload(add(transcript, 0x166c0)), f_q))
mstore(add(transcript, 0x18800), addmod(mload(add(transcript, 0x18760)), mload(add(transcript, 0x187c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3060)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x3080)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x30a0)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x30c0)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x18820), result)        }
mstore(add(transcript, 0x18840), mulmod(mload(add(transcript, 0x18820)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x18860), mulmod(sub(f_q, mload(add(transcript, 0x18840))), mload(add(transcript, 0x166e0)), f_q))
mstore(add(transcript, 0x18880), mulmod(1, mload(add(transcript, 0x166e0)), f_q))
mstore(add(transcript, 0x188a0), addmod(mload(add(transcript, 0x18800)), mload(add(transcript, 0x18860)), f_q))
{            let result := mulmod(mload(add(transcript, 0x30e0)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x3100)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x3120)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x3140)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x188c0), result)        }
mstore(add(transcript, 0x188e0), mulmod(mload(add(transcript, 0x188c0)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x18900), mulmod(sub(f_q, mload(add(transcript, 0x188e0))), mload(add(transcript, 0x16700)), f_q))
mstore(add(transcript, 0x18920), mulmod(1, mload(add(transcript, 0x16700)), f_q))
mstore(add(transcript, 0x18940), addmod(mload(add(transcript, 0x188a0)), mload(add(transcript, 0x18900)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3640)), mload(add(transcript, 0x15be0)), f_q)result := addmod(mulmod(mload(add(transcript, 0x3700)), mload(add(transcript, 0x15c00)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x3780)), mload(add(transcript, 0x15c20)), f_q), result, f_q)result := addmod(mulmod(mload(add(transcript, 0x3800)), mload(add(transcript, 0x15c40)), f_q), result, f_q)mstore(add(transcript, 0x18960), result)        }
mstore(add(transcript, 0x18980), mulmod(mload(add(transcript, 0x18960)), mload(add(transcript, 0x161c0)), f_q))
mstore(add(transcript, 0x189a0), mulmod(sub(f_q, mload(add(transcript, 0x18980))), mload(add(transcript, 0x16720)), f_q))
mstore(add(transcript, 0x189c0), mulmod(1, mload(add(transcript, 0x16720)), f_q))
mstore(add(transcript, 0x189e0), addmod(mload(add(transcript, 0x18940)), mload(add(transcript, 0x189a0)), f_q))
mstore(add(transcript, 0x18a00), mulmod(mload(add(transcript, 0x189e0)), 1, f_q))
mstore(add(transcript, 0x18a20), mulmod(mload(add(transcript, 0x17fc0)), 1, f_q))
mstore(add(transcript, 0x18a40), mulmod(mload(add(transcript, 0x18060)), 1, f_q))
mstore(add(transcript, 0x18a60), mulmod(mload(add(transcript, 0x18100)), 1, f_q))
mstore(add(transcript, 0x18a80), mulmod(mload(add(transcript, 0x181a0)), 1, f_q))
mstore(add(transcript, 0x18aa0), mulmod(mload(add(transcript, 0x18240)), 1, f_q))
mstore(add(transcript, 0x18ac0), mulmod(mload(add(transcript, 0x182e0)), 1, f_q))
mstore(add(transcript, 0x18ae0), mulmod(mload(add(transcript, 0x18380)), 1, f_q))
mstore(add(transcript, 0x18b00), mulmod(mload(add(transcript, 0x18420)), 1, f_q))
mstore(add(transcript, 0x18b20), mulmod(mload(add(transcript, 0x184c0)), 1, f_q))
mstore(add(transcript, 0x18b40), mulmod(mload(add(transcript, 0x18560)), 1, f_q))
mstore(add(transcript, 0x18b60), mulmod(mload(add(transcript, 0x18600)), 1, f_q))
mstore(add(transcript, 0x18b80), mulmod(mload(add(transcript, 0x186a0)), 1, f_q))
mstore(add(transcript, 0x18ba0), mulmod(mload(add(transcript, 0x18740)), 1, f_q))
mstore(add(transcript, 0x18bc0), mulmod(mload(add(transcript, 0x187e0)), 1, f_q))
mstore(add(transcript, 0x18be0), mulmod(mload(add(transcript, 0x18880)), 1, f_q))
mstore(add(transcript, 0x18c00), mulmod(mload(add(transcript, 0x18920)), 1, f_q))
mstore(add(transcript, 0x18c20), mulmod(mload(add(transcript, 0x189c0)), 1, f_q))
mstore(add(transcript, 0x18c40), mulmod(1, mload(add(transcript, 0x161e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3160)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x18c60), result)        }
mstore(add(transcript, 0x18c80), mulmod(mload(add(transcript, 0x18c60)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x18ca0), mulmod(sub(f_q, mload(add(transcript, 0x18c80))), 1, f_q))
mstore(add(transcript, 0x18cc0), mulmod(mload(add(transcript, 0x18c40)), 1, f_q))
{            let result := mulmod(mload(add(transcript, 0x3180)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x18ce0), result)        }
mstore(add(transcript, 0x18d00), mulmod(mload(add(transcript, 0x18ce0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x18d20), mulmod(sub(f_q, mload(add(transcript, 0x18d00))), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x18d40), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x60c0)), f_q))
mstore(add(transcript, 0x18d60), addmod(mload(add(transcript, 0x18ca0)), mload(add(transcript, 0x18d20)), f_q))
{            let result := mulmod(mload(add(transcript, 0x31a0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x18d80), result)        }
mstore(add(transcript, 0x18da0), mulmod(mload(add(transcript, 0x18d80)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x18dc0), mulmod(sub(f_q, mload(add(transcript, 0x18da0))), mload(add(transcript, 0x16540)), f_q))
mstore(add(transcript, 0x18de0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16540)), f_q))
mstore(add(transcript, 0x18e00), addmod(mload(add(transcript, 0x18d60)), mload(add(transcript, 0x18dc0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3240)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x18e20), result)        }
mstore(add(transcript, 0x18e40), mulmod(mload(add(transcript, 0x18e20)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x18e60), mulmod(sub(f_q, mload(add(transcript, 0x18e40))), mload(add(transcript, 0x16560)), f_q))
mstore(add(transcript, 0x18e80), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16560)), f_q))
mstore(add(transcript, 0x18ea0), addmod(mload(add(transcript, 0x18e00)), mload(add(transcript, 0x18e60)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3260)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x18ec0), result)        }
mstore(add(transcript, 0x18ee0), mulmod(mload(add(transcript, 0x18ec0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x18f00), mulmod(sub(f_q, mload(add(transcript, 0x18ee0))), mload(add(transcript, 0x16580)), f_q))
mstore(add(transcript, 0x18f20), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16580)), f_q))
mstore(add(transcript, 0x18f40), addmod(mload(add(transcript, 0x18ea0)), mload(add(transcript, 0x18f00)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3280)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x18f60), result)        }
mstore(add(transcript, 0x18f80), mulmod(mload(add(transcript, 0x18f60)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x18fa0), mulmod(sub(f_q, mload(add(transcript, 0x18f80))), mload(add(transcript, 0x165a0)), f_q))
mstore(add(transcript, 0x18fc0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x165a0)), f_q))
mstore(add(transcript, 0x18fe0), addmod(mload(add(transcript, 0x18f40)), mload(add(transcript, 0x18fa0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x32a0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19000), result)        }
mstore(add(transcript, 0x19020), mulmod(mload(add(transcript, 0x19000)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19040), mulmod(sub(f_q, mload(add(transcript, 0x19020))), mload(add(transcript, 0x165c0)), f_q))
mstore(add(transcript, 0x19060), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x165c0)), f_q))
mstore(add(transcript, 0x19080), addmod(mload(add(transcript, 0x18fe0)), mload(add(transcript, 0x19040)), f_q))
{            let result := mulmod(mload(add(transcript, 0x32c0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x190a0), result)        }
mstore(add(transcript, 0x190c0), mulmod(mload(add(transcript, 0x190a0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x190e0), mulmod(sub(f_q, mload(add(transcript, 0x190c0))), mload(add(transcript, 0x165e0)), f_q))
mstore(add(transcript, 0x19100), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x165e0)), f_q))
mstore(add(transcript, 0x19120), addmod(mload(add(transcript, 0x19080)), mload(add(transcript, 0x190e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x32e0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19140), result)        }
mstore(add(transcript, 0x19160), mulmod(mload(add(transcript, 0x19140)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19180), mulmod(sub(f_q, mload(add(transcript, 0x19160))), mload(add(transcript, 0x16600)), f_q))
mstore(add(transcript, 0x191a0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16600)), f_q))
mstore(add(transcript, 0x191c0), addmod(mload(add(transcript, 0x19120)), mload(add(transcript, 0x19180)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3300)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x191e0), result)        }
mstore(add(transcript, 0x19200), mulmod(mload(add(transcript, 0x191e0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19220), mulmod(sub(f_q, mload(add(transcript, 0x19200))), mload(add(transcript, 0x16620)), f_q))
mstore(add(transcript, 0x19240), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16620)), f_q))
mstore(add(transcript, 0x19260), addmod(mload(add(transcript, 0x191c0)), mload(add(transcript, 0x19220)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3320)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19280), result)        }
mstore(add(transcript, 0x192a0), mulmod(mload(add(transcript, 0x19280)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x192c0), mulmod(sub(f_q, mload(add(transcript, 0x192a0))), mload(add(transcript, 0x16640)), f_q))
mstore(add(transcript, 0x192e0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16640)), f_q))
mstore(add(transcript, 0x19300), addmod(mload(add(transcript, 0x19260)), mload(add(transcript, 0x192c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x33c0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19320), result)        }
mstore(add(transcript, 0x19340), mulmod(mload(add(transcript, 0x19320)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19360), mulmod(sub(f_q, mload(add(transcript, 0x19340))), mload(add(transcript, 0x16660)), f_q))
mstore(add(transcript, 0x19380), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16660)), f_q))
mstore(add(transcript, 0x193a0), addmod(mload(add(transcript, 0x19300)), mload(add(transcript, 0x19360)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3540)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x193c0), result)        }
mstore(add(transcript, 0x193e0), mulmod(mload(add(transcript, 0x193c0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19400), mulmod(sub(f_q, mload(add(transcript, 0x193e0))), mload(add(transcript, 0x16680)), f_q))
mstore(add(transcript, 0x19420), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16680)), f_q))
mstore(add(transcript, 0x19440), addmod(mload(add(transcript, 0x193a0)), mload(add(transcript, 0x19400)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3560)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19460), result)        }
mstore(add(transcript, 0x19480), mulmod(mload(add(transcript, 0x19460)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x194a0), mulmod(sub(f_q, mload(add(transcript, 0x19480))), mload(add(transcript, 0x166a0)), f_q))
mstore(add(transcript, 0x194c0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x166a0)), f_q))
mstore(add(transcript, 0x194e0), addmod(mload(add(transcript, 0x19440)), mload(add(transcript, 0x194a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x35a0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19500), result)        }
mstore(add(transcript, 0x19520), mulmod(mload(add(transcript, 0x19500)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19540), mulmod(sub(f_q, mload(add(transcript, 0x19520))), mload(add(transcript, 0x166c0)), f_q))
mstore(add(transcript, 0x19560), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x166c0)), f_q))
mstore(add(transcript, 0x19580), addmod(mload(add(transcript, 0x194e0)), mload(add(transcript, 0x19540)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3680)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x195a0), result)        }
mstore(add(transcript, 0x195c0), mulmod(mload(add(transcript, 0x195a0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x195e0), mulmod(sub(f_q, mload(add(transcript, 0x195c0))), mload(add(transcript, 0x166e0)), f_q))
mstore(add(transcript, 0x19600), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x166e0)), f_q))
mstore(add(transcript, 0x19620), addmod(mload(add(transcript, 0x19580)), mload(add(transcript, 0x195e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x36a0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19640), result)        }
mstore(add(transcript, 0x19660), mulmod(mload(add(transcript, 0x19640)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19680), mulmod(sub(f_q, mload(add(transcript, 0x19660))), mload(add(transcript, 0x16700)), f_q))
mstore(add(transcript, 0x196a0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16700)), f_q))
mstore(add(transcript, 0x196c0), addmod(mload(add(transcript, 0x19620)), mload(add(transcript, 0x19680)), f_q))
{            let result := mulmod(mload(add(transcript, 0x36c0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x196e0), result)        }
mstore(add(transcript, 0x19700), mulmod(mload(add(transcript, 0x196e0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19720), mulmod(sub(f_q, mload(add(transcript, 0x19700))), mload(add(transcript, 0x16720)), f_q))
mstore(add(transcript, 0x19740), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16720)), f_q))
mstore(add(transcript, 0x19760), addmod(mload(add(transcript, 0x196c0)), mload(add(transcript, 0x19720)), f_q))
{            let result := mulmod(mload(add(transcript, 0x36e0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19780), result)        }
mstore(add(transcript, 0x197a0), mulmod(mload(add(transcript, 0x19780)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x197c0), mulmod(sub(f_q, mload(add(transcript, 0x197a0))), mload(add(transcript, 0x16740)), f_q))
mstore(add(transcript, 0x197e0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16740)), f_q))
mstore(add(transcript, 0x19800), addmod(mload(add(transcript, 0x19760)), mload(add(transcript, 0x197c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3720)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19820), result)        }
mstore(add(transcript, 0x19840), mulmod(mload(add(transcript, 0x19820)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19860), mulmod(sub(f_q, mload(add(transcript, 0x19840))), mload(add(transcript, 0x16760)), f_q))
mstore(add(transcript, 0x19880), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16760)), f_q))
mstore(add(transcript, 0x198a0), addmod(mload(add(transcript, 0x19800)), mload(add(transcript, 0x19860)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3740)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x198c0), result)        }
mstore(add(transcript, 0x198e0), mulmod(mload(add(transcript, 0x198c0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19900), mulmod(sub(f_q, mload(add(transcript, 0x198e0))), mload(add(transcript, 0x16780)), f_q))
mstore(add(transcript, 0x19920), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16780)), f_q))
mstore(add(transcript, 0x19940), addmod(mload(add(transcript, 0x198a0)), mload(add(transcript, 0x19900)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3760)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19960), result)        }
mstore(add(transcript, 0x19980), mulmod(mload(add(transcript, 0x19960)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x199a0), mulmod(sub(f_q, mload(add(transcript, 0x19980))), mload(add(transcript, 0x167a0)), f_q))
mstore(add(transcript, 0x199c0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x167a0)), f_q))
mstore(add(transcript, 0x199e0), addmod(mload(add(transcript, 0x19940)), mload(add(transcript, 0x199a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x37a0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19a00), result)        }
mstore(add(transcript, 0x19a20), mulmod(mload(add(transcript, 0x19a00)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19a40), mulmod(sub(f_q, mload(add(transcript, 0x19a20))), mload(add(transcript, 0x167c0)), f_q))
mstore(add(transcript, 0x19a60), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x167c0)), f_q))
mstore(add(transcript, 0x19a80), addmod(mload(add(transcript, 0x199e0)), mload(add(transcript, 0x19a40)), f_q))
{            let result := mulmod(mload(add(transcript, 0x37c0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19aa0), result)        }
mstore(add(transcript, 0x19ac0), mulmod(mload(add(transcript, 0x19aa0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19ae0), mulmod(sub(f_q, mload(add(transcript, 0x19ac0))), mload(add(transcript, 0x167e0)), f_q))
mstore(add(transcript, 0x19b00), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x167e0)), f_q))
mstore(add(transcript, 0x19b20), addmod(mload(add(transcript, 0x19a80)), mload(add(transcript, 0x19ae0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x37e0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19b40), result)        }
mstore(add(transcript, 0x19b60), mulmod(mload(add(transcript, 0x19b40)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19b80), mulmod(sub(f_q, mload(add(transcript, 0x19b60))), mload(add(transcript, 0x16800)), f_q))
mstore(add(transcript, 0x19ba0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16800)), f_q))
mstore(add(transcript, 0x19bc0), addmod(mload(add(transcript, 0x19b20)), mload(add(transcript, 0x19b80)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3820)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19be0), result)        }
mstore(add(transcript, 0x19c00), mulmod(mload(add(transcript, 0x19be0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19c20), mulmod(sub(f_q, mload(add(transcript, 0x19c00))), mload(add(transcript, 0x16820)), f_q))
mstore(add(transcript, 0x19c40), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16820)), f_q))
mstore(add(transcript, 0x19c60), addmod(mload(add(transcript, 0x19bc0)), mload(add(transcript, 0x19c20)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3840)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19c80), result)        }
mstore(add(transcript, 0x19ca0), mulmod(mload(add(transcript, 0x19c80)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19cc0), mulmod(sub(f_q, mload(add(transcript, 0x19ca0))), mload(add(transcript, 0x16840)), f_q))
mstore(add(transcript, 0x19ce0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16840)), f_q))
mstore(add(transcript, 0x19d00), addmod(mload(add(transcript, 0x19c60)), mload(add(transcript, 0x19cc0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x3860)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19d20), result)        }
mstore(add(transcript, 0x19d40), mulmod(mload(add(transcript, 0x19d20)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19d60), mulmod(sub(f_q, mload(add(transcript, 0x19d40))), mload(add(transcript, 0x16860)), f_q))
mstore(add(transcript, 0x19d80), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16860)), f_q))
mstore(add(transcript, 0x19da0), addmod(mload(add(transcript, 0x19d00)), mload(add(transcript, 0x19d60)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5220)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19dc0), result)        }
mstore(add(transcript, 0x19de0), mulmod(mload(add(transcript, 0x19dc0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19e00), mulmod(sub(f_q, mload(add(transcript, 0x19de0))), mload(add(transcript, 0x16880)), f_q))
mstore(add(transcript, 0x19e20), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16880)), f_q))
mstore(add(transcript, 0x19e40), addmod(mload(add(transcript, 0x19da0)), mload(add(transcript, 0x19e00)), f_q))
{            let result := mulmod(mload(add(transcript, 0x52c0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19e60), result)        }
mstore(add(transcript, 0x19e80), mulmod(mload(add(transcript, 0x19e60)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19ea0), mulmod(sub(f_q, mload(add(transcript, 0x19e80))), mload(add(transcript, 0x168a0)), f_q))
mstore(add(transcript, 0x19ec0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x168a0)), f_q))
mstore(add(transcript, 0x19ee0), addmod(mload(add(transcript, 0x19e40)), mload(add(transcript, 0x19ea0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5360)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19f00), result)        }
mstore(add(transcript, 0x19f20), mulmod(mload(add(transcript, 0x19f00)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19f40), mulmod(sub(f_q, mload(add(transcript, 0x19f20))), mload(add(transcript, 0x168c0)), f_q))
mstore(add(transcript, 0x19f60), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x168c0)), f_q))
mstore(add(transcript, 0x19f80), addmod(mload(add(transcript, 0x19ee0)), mload(add(transcript, 0x19f40)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5400)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x19fa0), result)        }
mstore(add(transcript, 0x19fc0), mulmod(mload(add(transcript, 0x19fa0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x19fe0), mulmod(sub(f_q, mload(add(transcript, 0x19fc0))), mload(add(transcript, 0x168e0)), f_q))
mstore(add(transcript, 0x1a000), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x168e0)), f_q))
mstore(add(transcript, 0x1a020), addmod(mload(add(transcript, 0x19f80)), mload(add(transcript, 0x19fe0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x54a0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a040), result)        }
mstore(add(transcript, 0x1a060), mulmod(mload(add(transcript, 0x1a040)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a080), mulmod(sub(f_q, mload(add(transcript, 0x1a060))), mload(add(transcript, 0x16900)), f_q))
mstore(add(transcript, 0x1a0a0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16900)), f_q))
mstore(add(transcript, 0x1a0c0), addmod(mload(add(transcript, 0x1a020)), mload(add(transcript, 0x1a080)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5540)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a0e0), result)        }
mstore(add(transcript, 0x1a100), mulmod(mload(add(transcript, 0x1a0e0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a120), mulmod(sub(f_q, mload(add(transcript, 0x1a100))), mload(add(transcript, 0x16920)), f_q))
mstore(add(transcript, 0x1a140), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16920)), f_q))
mstore(add(transcript, 0x1a160), addmod(mload(add(transcript, 0x1a0c0)), mload(add(transcript, 0x1a120)), f_q))
{            let result := mulmod(mload(add(transcript, 0x55e0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a180), result)        }
mstore(add(transcript, 0x1a1a0), mulmod(mload(add(transcript, 0x1a180)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a1c0), mulmod(sub(f_q, mload(add(transcript, 0x1a1a0))), mload(add(transcript, 0x16940)), f_q))
mstore(add(transcript, 0x1a1e0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16940)), f_q))
mstore(add(transcript, 0x1a200), addmod(mload(add(transcript, 0x1a160)), mload(add(transcript, 0x1a1c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5680)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a220), result)        }
mstore(add(transcript, 0x1a240), mulmod(mload(add(transcript, 0x1a220)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a260), mulmod(sub(f_q, mload(add(transcript, 0x1a240))), mload(add(transcript, 0x16960)), f_q))
mstore(add(transcript, 0x1a280), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16960)), f_q))
mstore(add(transcript, 0x1a2a0), addmod(mload(add(transcript, 0x1a200)), mload(add(transcript, 0x1a260)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5720)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a2c0), result)        }
mstore(add(transcript, 0x1a2e0), mulmod(mload(add(transcript, 0x1a2c0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a300), mulmod(sub(f_q, mload(add(transcript, 0x1a2e0))), mload(add(transcript, 0x16980)), f_q))
mstore(add(transcript, 0x1a320), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16980)), f_q))
mstore(add(transcript, 0x1a340), addmod(mload(add(transcript, 0x1a2a0)), mload(add(transcript, 0x1a300)), f_q))
{            let result := mulmod(mload(add(transcript, 0x57c0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a360), result)        }
mstore(add(transcript, 0x1a380), mulmod(mload(add(transcript, 0x1a360)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a3a0), mulmod(sub(f_q, mload(add(transcript, 0x1a380))), mload(add(transcript, 0x169a0)), f_q))
mstore(add(transcript, 0x1a3c0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x169a0)), f_q))
mstore(add(transcript, 0x1a3e0), addmod(mload(add(transcript, 0x1a340)), mload(add(transcript, 0x1a3a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5860)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a400), result)        }
mstore(add(transcript, 0x1a420), mulmod(mload(add(transcript, 0x1a400)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a440), mulmod(sub(f_q, mload(add(transcript, 0x1a420))), mload(add(transcript, 0x169c0)), f_q))
mstore(add(transcript, 0x1a460), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x169c0)), f_q))
mstore(add(transcript, 0x1a480), addmod(mload(add(transcript, 0x1a3e0)), mload(add(transcript, 0x1a440)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5900)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a4a0), result)        }
mstore(add(transcript, 0x1a4c0), mulmod(mload(add(transcript, 0x1a4a0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a4e0), mulmod(sub(f_q, mload(add(transcript, 0x1a4c0))), mload(add(transcript, 0x169e0)), f_q))
mstore(add(transcript, 0x1a500), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x169e0)), f_q))
mstore(add(transcript, 0x1a520), addmod(mload(add(transcript, 0x1a480)), mload(add(transcript, 0x1a4e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x59a0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a540), result)        }
mstore(add(transcript, 0x1a560), mulmod(mload(add(transcript, 0x1a540)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a580), mulmod(sub(f_q, mload(add(transcript, 0x1a560))), mload(add(transcript, 0x16a00)), f_q))
mstore(add(transcript, 0x1a5a0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16a00)), f_q))
mstore(add(transcript, 0x1a5c0), addmod(mload(add(transcript, 0x1a520)), mload(add(transcript, 0x1a580)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5a40)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a5e0), result)        }
mstore(add(transcript, 0x1a600), mulmod(mload(add(transcript, 0x1a5e0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a620), mulmod(sub(f_q, mload(add(transcript, 0x1a600))), mload(add(transcript, 0x16a20)), f_q))
mstore(add(transcript, 0x1a640), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16a20)), f_q))
mstore(add(transcript, 0x1a660), addmod(mload(add(transcript, 0x1a5c0)), mload(add(transcript, 0x1a620)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5ae0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a680), result)        }
mstore(add(transcript, 0x1a6a0), mulmod(mload(add(transcript, 0x1a680)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a6c0), mulmod(sub(f_q, mload(add(transcript, 0x1a6a0))), mload(add(transcript, 0x16a40)), f_q))
mstore(add(transcript, 0x1a6e0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16a40)), f_q))
mstore(add(transcript, 0x1a700), addmod(mload(add(transcript, 0x1a660)), mload(add(transcript, 0x1a6c0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5b80)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a720), result)        }
mstore(add(transcript, 0x1a740), mulmod(mload(add(transcript, 0x1a720)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a760), mulmod(sub(f_q, mload(add(transcript, 0x1a740))), mload(add(transcript, 0x16a60)), f_q))
mstore(add(transcript, 0x1a780), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16a60)), f_q))
mstore(add(transcript, 0x1a7a0), addmod(mload(add(transcript, 0x1a700)), mload(add(transcript, 0x1a760)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5c20)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a7c0), result)        }
mstore(add(transcript, 0x1a7e0), mulmod(mload(add(transcript, 0x1a7c0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a800), mulmod(sub(f_q, mload(add(transcript, 0x1a7e0))), mload(add(transcript, 0x16a80)), f_q))
mstore(add(transcript, 0x1a820), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16a80)), f_q))
mstore(add(transcript, 0x1a840), addmod(mload(add(transcript, 0x1a7a0)), mload(add(transcript, 0x1a800)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5cc0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a860), result)        }
mstore(add(transcript, 0x1a880), mulmod(mload(add(transcript, 0x1a860)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a8a0), mulmod(sub(f_q, mload(add(transcript, 0x1a880))), mload(add(transcript, 0x16aa0)), f_q))
mstore(add(transcript, 0x1a8c0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16aa0)), f_q))
mstore(add(transcript, 0x1a8e0), addmod(mload(add(transcript, 0x1a840)), mload(add(transcript, 0x1a8a0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5d60)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a900), result)        }
mstore(add(transcript, 0x1a920), mulmod(mload(add(transcript, 0x1a900)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a940), mulmod(sub(f_q, mload(add(transcript, 0x1a920))), mload(add(transcript, 0x16ac0)), f_q))
mstore(add(transcript, 0x1a960), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16ac0)), f_q))
mstore(add(transcript, 0x1a980), addmod(mload(add(transcript, 0x1a8e0)), mload(add(transcript, 0x1a940)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5e00)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1a9a0), result)        }
mstore(add(transcript, 0x1a9c0), mulmod(mload(add(transcript, 0x1a9a0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1a9e0), mulmod(sub(f_q, mload(add(transcript, 0x1a9c0))), mload(add(transcript, 0x16ae0)), f_q))
mstore(add(transcript, 0x1aa00), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16ae0)), f_q))
mstore(add(transcript, 0x1aa20), addmod(mload(add(transcript, 0x1a980)), mload(add(transcript, 0x1a9e0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5ea0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1aa40), result)        }
mstore(add(transcript, 0x1aa60), mulmod(mload(add(transcript, 0x1aa40)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1aa80), mulmod(sub(f_q, mload(add(transcript, 0x1aa60))), mload(add(transcript, 0x16b00)), f_q))
mstore(add(transcript, 0x1aaa0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16b00)), f_q))
mstore(add(transcript, 0x1aac0), addmod(mload(add(transcript, 0x1aa20)), mload(add(transcript, 0x1aa80)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5f40)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1aae0), result)        }
mstore(add(transcript, 0x1ab00), mulmod(mload(add(transcript, 0x1aae0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1ab20), mulmod(sub(f_q, mload(add(transcript, 0x1ab00))), mload(add(transcript, 0x16b20)), f_q))
mstore(add(transcript, 0x1ab40), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16b20)), f_q))
mstore(add(transcript, 0x1ab60), addmod(mload(add(transcript, 0x1aac0)), mload(add(transcript, 0x1ab20)), f_q))
{            let result := mulmod(mload(add(transcript, 0x5fe0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1ab80), result)        }
mstore(add(transcript, 0x1aba0), mulmod(mload(add(transcript, 0x1ab80)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1abc0), mulmod(sub(f_q, mload(add(transcript, 0x1aba0))), mload(add(transcript, 0x16b40)), f_q))
mstore(add(transcript, 0x1abe0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16b40)), f_q))
mstore(add(transcript, 0x1ac00), addmod(mload(add(transcript, 0x1ab60)), mload(add(transcript, 0x1abc0)), f_q))
{            let result := mulmod(mload(add(transcript, 0x6080)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1ac20), result)        }
mstore(add(transcript, 0x1ac40), mulmod(mload(add(transcript, 0x1ac20)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1ac60), mulmod(sub(f_q, mload(add(transcript, 0x1ac40))), mload(add(transcript, 0x16b60)), f_q))
mstore(add(transcript, 0x1ac80), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16b60)), f_q))
mstore(add(transcript, 0x1aca0), addmod(mload(add(transcript, 0x1ac00)), mload(add(transcript, 0x1ac60)), f_q))
{            let result := mulmod(mload(add(transcript, 0x38c0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1acc0), result)        }
mstore(add(transcript, 0x1ace0), mulmod(mload(add(transcript, 0x1acc0)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1ad00), mulmod(sub(f_q, mload(add(transcript, 0x1ace0))), mload(add(transcript, 0x16b80)), f_q))
mstore(add(transcript, 0x1ad20), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16b80)), f_q))
mstore(add(transcript, 0x1ad40), addmod(mload(add(transcript, 0x1aca0)), mload(add(transcript, 0x1ad00)), f_q))
{            let result := mulmod(mload(add(transcript, 0x38e0)), mload(add(transcript, 0x15ce0)), f_q)mstore(add(transcript, 0x1ad60), result)        }
mstore(add(transcript, 0x1ad80), mulmod(mload(add(transcript, 0x1ad60)), mload(add(transcript, 0x164a0)), f_q))
mstore(add(transcript, 0x1ada0), mulmod(sub(f_q, mload(add(transcript, 0x1ad80))), mload(add(transcript, 0x16ba0)), f_q))
mstore(add(transcript, 0x1adc0), mulmod(mload(add(transcript, 0x18c40)), mload(add(transcript, 0x16ba0)), f_q))
mstore(add(transcript, 0x1ade0), addmod(mload(add(transcript, 0x1ad40)), mload(add(transcript, 0x1ada0)), f_q))

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
