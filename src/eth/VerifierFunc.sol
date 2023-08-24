// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "../VerifierFuncAbst.sol";

contract VerifierFunc<%ID%> is VerifierFuncAbst {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes32[] memory _transcript
    ) public view override returns (bool, bytes32[] memory) {
        bytes32[<%max_transcript_addr%>] memory transcript;
        for(uint i=0; i<_transcript.length; i++) {
            transcript[i] = _transcript[i];
        }
        assembly {{
            <%ASSEMBLY%>
        }}
        // transcriptBytes = abi.encode(transcript.length, transcript);
        bytes32[] memory newTranscript = new bytes32[](_transcript.length);
        for(uint i=0; i<_transcript.length; i++) {
            newTranscript[i] = transcript[i];
        }
        return (success, newTranscript);
    } 
}
