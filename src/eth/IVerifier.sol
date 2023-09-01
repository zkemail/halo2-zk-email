// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IHalo2Verifier {
    function verifyProof(
        address vk,
        bytes calldata proof,
        uint256[] calldata instances
    ) external view returns (bool);
}
