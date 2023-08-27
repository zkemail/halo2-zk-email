// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierBase.sol";

contract EmailVerifier {
    uint constant f_r =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    address public verifierBase;
    uint public maxHeaderBytes;
    uint public maxBodyBytes;

    struct EmailProofInstance {
        uint headerHashCommit;
        uint publicKeyHash;
        string[] headerSubstrs;
        uint[] headerSubstrStarts;
        string[] bodySubstrs;
        uint[] bodySubstrStarts;
    }

    constructor(
        address _verifierBase,
        uint _maxHeaderBytes,
        uint _maxBodyBytes
    ) {
        verifierBase = _verifierBase;
        maxHeaderBytes = _maxHeaderBytes;
        maxBodyBytes = _maxBodyBytes;
    }

    function verifyEmail(
        EmailProofInstance memory instance,
        bytes memory proof
    ) public view {
        (
            bytes memory headerMaskedChars,
            bytes memory headerSubstrIds
        ) = getMaskedCharsAndIds(
                maxHeaderBytes,
                instance.headerSubstrs,
                instance.headerSubstrStarts
            );
        (
            bytes memory bodyMaskedChars,
            bytes memory bodySubstrIds
        ) = getMaskedCharsAndIds(
                maxBodyBytes,
                instance.bodySubstrs,
                instance.bodySubstrStarts
            );
        uint rlc = 0;
        uint coeff = instance.headerHashCommit;
        (rlc, coeff) = computeRLC(
            rlc,
            coeff,
            instance.headerHashCommit,
            headerMaskedChars
        );
        (rlc, coeff) = computeRLC(
            rlc,
            coeff,
            instance.headerHashCommit,
            headerSubstrIds
        );
        (rlc, coeff) = computeRLC(
            rlc,
            coeff,
            instance.headerHashCommit,
            bodyMaskedChars
        );
        (rlc, coeff) = computeRLC(
            rlc,
            coeff,
            instance.headerHashCommit,
            bodySubstrIds
        );

        VerifierBase verifier = VerifierBase(verifierBase);
        uint[] memory pubInputs = new uint[](3);
        pubInputs[0] = instance.headerHashCommit;
        pubInputs[1] = instance.publicKeyHash;
        pubInputs[2] = rlc;
        require(verifier.verify(pubInputs, proof), "invalid proof");
        // (bool success, bytes memory res) = address(verifier).staticcall(
        //     abi.encodeWithSignature("verify(uint256[],bytes)", pubInputs, proof)
        // );
        // if (!success) {
        //     bytes memory revertData = slice(res, 4, res.length - 4);
        //     require(false, abi.decode(revertData, (string)));
        // }
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

    // function slice(
    //     bytes memory _bytes,
    //     uint256 _start,
    //     uint256 _length
    // ) internal pure returns (bytes memory) {
    //     require(_length + 31 >= _length, "slice_overflow");
    //     require(_bytes.length >= _start + _length, "slice_outOfBounds");

    //     bytes memory tempBytes;

    //     assembly {
    //         switch iszero(_length)
    //         case 0 {
    //             // Get a location of some free memory and store it in tempBytes as
    //             // Solidity does for memory variables.
    //             tempBytes := mload(0x40)

    //             // The first word of the slice result is potentially a partial
    //             // word read from the original array. To read it, we calculate
    //             // the length of that partial word and start copying that many
    //             // bytes into the array. The first word we copy will start with
    //             // data we don't care about, but the last `lengthmod` bytes will
    //             // land at the beginning of the contents of the new array. When
    //             // we're done copying, we overwrite the full first word with
    //             // the actual length of the slice.
    //             let lengthmod := and(_length, 31)

    //             // The multiplication in the next line is necessary
    //             // because when slicing multiples of 32 bytes (lengthmod == 0)
    //             // the following copy loop was copying the origin's length
    //             // and then ending prematurely not copying everything it should.
    //             let mc := add(
    //                 add(tempBytes, lengthmod),
    //                 mul(0x20, iszero(lengthmod))
    //             )
    //             let end := add(mc, _length)

    //             for {
    //                 // The multiplication in the next line has the same exact purpose
    //                 // as the one above.
    //                 let cc := add(
    //                     add(
    //                         add(_bytes, lengthmod),
    //                         mul(0x20, iszero(lengthmod))
    //                     ),
    //                     _start
    //                 )
    //             } lt(mc, end) {
    //                 mc := add(mc, 0x20)
    //                 cc := add(cc, 0x20)
    //             } {
    //                 mstore(mc, mload(cc))
    //             }

    //             mstore(tempBytes, _length)

    //             //update free-memory pointer
    //             //allocating the array padded to 32 bytes like the compiler does now
    //             mstore(0x40, and(add(mc, 31), not(31)))
    //         }
    //         //if we want a zero-length slice let's just return a zero-length array
    //         default {
    //             tempBytes := mload(0x40)
    //             //zero out the 32 bytes slice we are about to return
    //             //we need to do it because Solidity does not garbage collect
    //             mstore(tempBytes, 0)

    //             mstore(0x40, add(tempBytes, 0x20))
    //         }
    //     }

    //     return tempBytes;
    // }
}
