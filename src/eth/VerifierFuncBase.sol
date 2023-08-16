// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierFuncAbst.sol";

contract VerifierFunc<%ID%> is VerifierFuncAbst {
    uint256 constant SIZE_LIMIT =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    bytes32 public transcript[<%max_transcript_addr%>];
    uint numVerifierFuncs;
    address public verifierFuncs[];


    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool _success
    ) public view returns (bool) {
        bool success = _success;
        assembly {{
            <%ASSEMBLY%>
        }}
        return success;
    }
}
