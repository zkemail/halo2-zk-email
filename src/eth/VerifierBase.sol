// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierFuncAbst.sol";

// MAX TRANSCRIPT ADDR: <%max_transcript_addr%>
contract VerifierBase {
    uint256 constant SIZE_LIMIT =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint numVerifierFuncs;
    address[] public verifierFuncs;
    uint public maxTranscriptAddr;

    constructor(address[] memory _verifierFuncs, uint _maxTranscriptAddr) {
        numVerifierFuncs = _verifierFuncs.length;
        verifierFuncs = _verifierFuncs;
        maxTranscriptAddr = _maxTranscriptAddr;
    }

    function verify(
        uint256[] memory pubInputs,
        bytes memory proof
    ) public view returns (bool) {
        bool success = true;
        bytes32[] memory transcript = new bytes32[](maxTranscriptAddr);
        for (uint i = 0; i < pubInputs.length; i++) {
            require(pubInputs[i] < SIZE_LIMIT);
        }
        for (uint i = 0; i < numVerifierFuncs; i++) {
            // (bool callSuccess, bytes memory callData) = verifierFuncs[i]
            //     .delegatecall(
            //         abi.encodeWithSignature(
            //             "verifyPartial(uint256[],bytes,bool,bytes32[])",
            //             pubInputs,
            //             proof,
            //             success,
            //             transcript
            //         )
            //     );
            // require(callSuccess);
            // (success, newTranscript) = abi.decode(callData, (bool));
            VerifierFuncAbst verifier = VerifierFuncAbst(verifierFuncs[i]);
            (bool newSuccess, bytes32[] memory newTranscript) = verifier
                .verifyPartial(pubInputs, proof, success, transcript);
            success = newSuccess;
            transcript = newTranscript;
        }
        return success;
    }
}
