// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

abstract contract VerifierFuncAbst {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes memory _transcript
    ) public view virtual returns (bool, bytes memory);
}
