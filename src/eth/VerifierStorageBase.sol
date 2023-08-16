// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierFuncAbst.sol";

contract VerifierStorage {
    uint256 constant SIZE_LIMIT =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    bytes32 public transcript[<%max_transcript_addr%>];
    uint numVerifierFuncs;
    address public verifierFuncs[];
    
    constructor(
        address[] memory _verifierFuncs
    ) {
        numVerifierFuncs = _verifierFuncs.length;
        for(uint i = 0; i < _verifierFuncs.length; i++) {
            verifierFuncs.push(_verifierFuncs[i]);
        }
    }

    function verify(
        uint256[] memory pubInputs,
        bytes memory proof
    ) public view returns (bool) {
        bool success = true;
        for (uint i = 0; i < pubInputs.length; i++) {
            require(pubInputs[i] < SIZE_LIMIT);
        }
        for (uint i = 0; i < numVerifierFuncs; i++) {
            (bool callSuccess, bytes memory callData) = verifierFuncs[i].delegatecall(abi.encodeWithSignature("verifyPartial(uint256[],bytes,bool)", pubInputs, proof, success));
            require(callSuccess);
            success = abi.decode(callData, (bool));
        }
        return success;
    }
}
