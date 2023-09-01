// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./IVerifier.sol";

contract EmailVerifier {
    uint constant f_r =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // address public verifierBase;
    address public vkAddr;
    address public verifierAddr;
    uint public maxHeaderBytes;
    uint public maxBodyBytes;

    constructor(
        address _vkAddr,
        address _verifierAddr,
        uint _maxHeaderBytes,
        uint _maxBodyBytes
    ) {
        vkAddr = _vkAddr;
        verifierAddr = _verifierAddr;
        maxHeaderBytes = _maxHeaderBytes;
        maxBodyBytes = _maxBodyBytes;
    }

    function verifyEmail(
        bytes memory instance,
        bytes memory proof
    ) public view {
        (
            uint headerHashCommit,
            uint publicKeyHash,
            string[] memory headerSubstrs,
            uint[] memory headerSubstrStarts,
            string[] memory bodySubstrs,
            uint[] memory bodySubstrStarts
        ) = abi.decode(
                instance,
                (uint, uint, string[], uint[], string[], uint[])
            );
        uint rlc = 0;
        uint coeff = headerHashCommit;
        bytes memory maskedChars;
        bytes memory substrIds;
        (maskedChars, substrIds) = getMaskedCharsAndIds(
            maxHeaderBytes,
            headerSubstrs,
            headerSubstrStarts
        );
        (rlc, coeff) = computeRLC(rlc, coeff, headerHashCommit, maskedChars);
        (rlc, coeff) = computeRLC(rlc, coeff, headerHashCommit, substrIds);
        (maskedChars, substrIds) = getMaskedCharsAndIds(
            maxBodyBytes,
            bodySubstrs,
            bodySubstrStarts
        );
        (rlc, coeff) = computeRLC(rlc, coeff, headerHashCommit, maskedChars);
        (rlc, coeff) = computeRLC(rlc, coeff, headerHashCommit, substrIds);

        // VerifierBase verifier = VerifierBase(verifierBase);
        uint[] memory instances = new uint[](3);
        instances[0] = headerHashCommit;
        instances[1] = publicKeyHash;
        instances[2] = rlc;
        // require(verifier.verify(pubInputs, proof), "invalid proof");
        IHalo2Verifier verifier = IHalo2Verifier(verifierAddr);
        require(
            verifier.verifyProof(vkAddr, proof, instances),
            "invalid proof"
        );
    }

    function getMaskedCharsAndIds(
        uint maxBytes,
        string[] memory substrs,
        uint[] memory substrStarts
    ) private pure returns (bytes memory, bytes memory) {
        bytes memory expectedMaskedChars = new bytes(maxBytes);
        bytes memory expectedSubstrIds = new bytes(maxBytes);
        for (uint i = 0; i < substrs.length; i++) {
            uint startIdx = substrStarts[i];
            for (uint j = 0; j < bytes(substrs[i]).length; j++) {
                expectedMaskedChars[startIdx + j] = bytes(substrs[i])[j];
                expectedSubstrIds[startIdx + j] = bytes1(uint8(i + 1));
            }
        }
        return (expectedMaskedChars, expectedSubstrIds);
    }

    function computeRLC(
        uint rlc,
        uint coeff,
        uint rand,
        bytes memory inputs
    ) private pure returns (uint, uint) {
        uint muled = 0;
        uint input_byte = 0;
        for (uint i = 0; i < inputs.length; i++) {
            input_byte = uint(uint8(inputs[i]));
            assembly {
                muled := mulmod(input_byte, coeff, f_r)
                rlc := addmod(rlc, muled, f_r)
                coeff := mulmod(coeff, rand, f_r)
            }
        }
        return (rlc, coeff);
    }
}
