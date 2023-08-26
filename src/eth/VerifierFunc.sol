// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "../VerifierFuncAbst.sol";

contract VerifierFunc<%ID%> is VerifierFuncAbst {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes memory _transcript
    ) public view override returns (bool, bytes memory) {
        bytes32[<%max_transcript_addr%>] memory transcript;
        // require(_transcript.length == <%max_transcript_addr%>, "transcript length is not <%max_transcript_addr%>");
        if(_transcript.length != 0) {
            transcript = abi.decode(_transcript, (bytes32[<%max_transcript_addr%>]));
        }
        // for(uint i=0; i<_transcript.length; i++) {
        //     transcript[i] = _transcript[i];
        // }
        assembly {{
            <%ASSEMBLY%>
        }}
        bytes memory transcriptBytes = abi.encode(transcript);
        // bytes32[] memory newTranscript = new bytes32[](<%max_transcript_addr%>);
        // for(uint i=0; i<_transcript.length; i++) {
        //     newTranscript[i] = transcript[i];
        // }
        // require(newTranscript.length == <%max_transcript_addr%>, "newTranscript length is not <%max_transcript_addr%>");
        return (success, transcriptBytes);
    } 
}
