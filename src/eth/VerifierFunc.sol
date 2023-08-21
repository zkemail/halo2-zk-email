// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "../VerifierFuncAbst.sol";

contract VerifierFunc<%ID%> is VerifierFuncAbst {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes32[] memory transcript
    ) public view override returns (bool, bytes32[] memory) {
        assembly {{
            <%ASSEMBLY%>
        }}
        return (success, transcript);
    } 
}
