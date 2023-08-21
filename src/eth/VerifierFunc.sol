// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierFuncAbst.sol";

contract VerifierFunc<%ID%> is VerifierFuncAbst {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes32[] memory transcript
    ) public view returns (bool, bytes32[] memory) {
        assembly {{
            <%ASSEMBLY%>
        }}
        return (success, transcript);
        }
    } 
}
