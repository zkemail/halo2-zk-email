// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "./VerifierBase.sol";

contract EmailVerifier {
    address public sha256HeaderVerifier;
    address public signVerifyVerifier;
    address public regexHeaderVerifier;
    address public sha256HeaderMaskedCharsVerifier;
    address public sha256HeaderSubstrIdsVerifier;
    address public regexBodyHashVerifier;
    address public charsShiftBodyHashVerifier;
    address public sha256BodyVerifier;
    address public base64Verifier;
    address public regexBodyVerifier;
    address public sha256BodyMaskedCharsVerifier;
    address public sha256BodySubstrIdsVerifier;
    bool public headerExposeSubstrs;
    bool public bodyEnable;
    bool public bodyExposeSubstrs;
    uint public maxHeaderBytes;
    uint public maxBodyBytes;

    struct EmailProofInstance {
        uint headerBytesCommit;
        uint headerHashCommit;
        uint publicKeyNHash;
        uint tag;
        uint headerMaskedCharsCommit;
        uint headerSubstrIdsCommit;
        string[] headerSubstrs;
        uint[] headerSubstrIdxes;
        uint bodyhashMaskedCharsCommit;
        uint bodyhashSubstrIdsCommit;
        uint bodyhashBase64Commit;
        uint bodyBytesCommit;
        uint bodyhashCommit;
        uint bodyMaskedCharsCommit;
        uint bodySubstrIdsCommit;
        string[] bodySubstrs;
        uint[] bodySubstrIdxes;
    }

    constructor(bytes memory _initParams) {
        // (
        //     sha256HeaderVerifier,
        //     signVerifyVerifier,
        //     regexHeaderVerifier,
        //     sha256HeaderMaskedCharsVerifier,
        //     sha256HeaderSubstrIdsVerifier,
        //     regexBodyHashVerifier,
        //     charsShiftBodyHashVerifier,
        //     sha256BodyVerifier,
        //     base64Verifier,
        //     regexBodyVerifier,
        //     sha256BodyMaskedCharsVerifier,
        //     sha256BodySubstrIdsVerifier,
        //     headerExposeSubstrs,
        //     bodyEnable,
        //     bodyExposeSubstrs,
        //     maxHeaderBytes,
        //     maxBodyBytes
        // ) = abi.decode(
        //     _initParams,
        //     (address, address, address, address, address, address,address, address, address, address, address, address, bool, bool, bool, uint, uint)
        // );
        bytes memory decoded;
        (decoded, maxBodyBytes) = abi.decode(_initParams, (bytes, uint));
        (decoded, maxHeaderBytes) = abi.decode(decoded, (bytes, uint));
        (decoded, bodyExposeSubstrs) = abi.decode(decoded, (bytes, bool));
        (decoded, bodyEnable) = abi.decode(decoded, (bytes, bool));
        (decoded, headerExposeSubstrs) = abi.decode(decoded, (bytes, bool));
        (decoded, sha256BodySubstrIdsVerifier) = abi.decode(
            decoded,
            (bytes, address)
        );
        (decoded, sha256BodyMaskedCharsVerifier) = abi.decode(
            decoded,
            (bytes, address)
        );
        (decoded, regexBodyVerifier) = abi.decode(decoded, (bytes, address));
        (decoded, base64Verifier) = abi.decode(decoded, (bytes, address));
        (decoded, sha256BodyVerifier) = abi.decode(decoded, (bytes, address));
        (decoded, charsShiftBodyHashVerifier) = abi.decode(
            decoded,
            (bytes, address)
        );
        (decoded, regexBodyHashVerifier) = abi.decode(
            decoded,
            (bytes, address)
        );
        (decoded, sha256HeaderSubstrIdsVerifier) = abi.decode(
            decoded,
            (bytes, address)
        );
        (decoded, sha256HeaderMaskedCharsVerifier) = abi.decode(
            decoded,
            (bytes, address)
        );
        (decoded, regexHeaderVerifier) = abi.decode(decoded, (bytes, address));
        (sha256HeaderVerifier, signVerifyVerifier) = abi.decode(
            decoded,
            (address, address)
        );
    }

    function verifyEmail(
        EmailProofInstance memory instance,
        bytes[] memory proofs
    ) public view {
        uint proofIdx = 0;
        VerifierBase sha256HeaderVerifierBase = VerifierBase(
            sha256HeaderVerifier
        );
        uint256[] memory sha256HeaderVerifierIns = new uint256[](2);
        sha256HeaderVerifierIns[0] = instance.headerBytesCommit;
        sha256HeaderVerifierIns[1] = instance.headerHashCommit;
        require(
            sha256HeaderVerifierBase.verify(
                sha256HeaderVerifierIns,
                proofs[proofIdx]
            ),
            "invalid sha256HeaderVerifier proof"
        );
        proofIdx++;
        VerifierBase signVerifyVerifierBase = VerifierBase(signVerifyVerifier);
        uint256[] memory signVerifyVerifierIns = new uint256[](3);
        signVerifyVerifierIns[0] = instance.publicKeyNHash;
        signVerifyVerifierIns[1] = instance.headerHashCommit;
        signVerifyVerifierIns[2] = instance.tag;
        require(
            signVerifyVerifierBase.verify(
                signVerifyVerifierIns,
                proofs[proofIdx]
            ),
            "invalid signVerifyVerifier proof"
        );
        proofIdx++;
        VerifierBase regexHeaderVerifierBase = VerifierBase(
            regexHeaderVerifier
        );
        uint256[] memory regexHeaderVerifierIns = new uint256[](3);
        regexHeaderVerifierIns[0] = instance.headerBytesCommit;
        regexHeaderVerifierIns[1] = instance.headerMaskedCharsCommit;
        regexHeaderVerifierIns[2] = instance.headerSubstrIdsCommit;
        require(
            regexHeaderVerifierBase.verify(
                regexHeaderVerifierIns,
                proofs[proofIdx]
            ),
            "invalid regexHeaderVerifier proof"
        );
        proofIdx++;
        if (headerExposeSubstrs) {
            proofIdx = verifyHeaderSubstrs(instance, proofs, proofIdx);
        }
        if (bodyEnable) {
            proofIdx = verifyBody(instance, proofs, proofIdx);
        }
    }

    function verifyHeaderSubstrs(
        EmailProofInstance memory instance,
        bytes[] memory proofs,
        uint _proofIdx
    ) private view returns (uint) {
        uint proofIdx = _proofIdx;
        bytes memory expectedHeaderMaskedChars = new bytes(maxHeaderBytes);
        bytes memory expectedHeaderSubstrIds = new bytes(maxHeaderBytes);
        for (uint i = 0; i < instance.headerSubstrs.length; i++) {
            uint startIdx = instance.headerSubstrIdxes[i];
            for (uint j = 0; j < bytes(instance.headerSubstrs[i]).length; j++) {
                expectedHeaderMaskedChars[startIdx + j] = bytes(
                    instance.headerSubstrs[i]
                )[j];
                expectedHeaderSubstrIds[startIdx + j] = bytes1(uint8(i + 1));
            }
        }
        VerifierBase sha256HeaderMaskedCharsVerifierBase = VerifierBase(
            sha256HeaderMaskedCharsVerifier
        );
        uint256[] memory sha256HeaderMaskedCharsVerifierIns = new uint256[](3);
        sha256HeaderMaskedCharsVerifierIns[0] = instance
            .headerMaskedCharsCommit;
        bytes32 sha256Hash = sha256(expectedHeaderMaskedChars);
        uint coeff = 1;
        for (uint i = 0; i < 31; i++) {
            sha256HeaderMaskedCharsVerifierIns[1] += (coeff *
                uint(uint8(sha256Hash[i])));
            coeff = coeff << 8;
        }
        sha256HeaderMaskedCharsVerifierIns[2] = uint(uint8(sha256Hash[31]));
        require(
            sha256HeaderMaskedCharsVerifierBase.verify(
                sha256HeaderMaskedCharsVerifierIns,
                proofs[proofIdx]
            ),
            "invalid sha256HeaderMaskedCharsVerifier proof"
        );
        proofIdx += 1;
        VerifierBase sha256HeaderSubstrIdsVerifierBase = VerifierBase(
            sha256HeaderSubstrIdsVerifier
        );
        uint256[] memory sha256HeaderSubstrIdsVerifierIns = new uint256[](3);
        sha256HeaderSubstrIdsVerifierIns[0] = instance.headerSubstrIdsCommit;
        sha256Hash = sha256(expectedHeaderSubstrIds);
        coeff = 1;
        for (uint i = 0; i < 31; i++) {
            sha256HeaderSubstrIdsVerifierIns[1] += (coeff *
                uint(uint8(sha256Hash[i])));
            coeff = coeff << 8;
        }
        sha256HeaderSubstrIdsVerifierIns[2] = uint(uint8(sha256Hash[31]));
        require(
            sha256HeaderSubstrIdsVerifierBase.verify(
                sha256HeaderSubstrIdsVerifierIns,
                proofs[proofIdx]
            ),
            "invalid sha256HeaderSubstrIdsVerifier proof"
        );
        proofIdx += 1;
        return proofIdx;
    }

    function verifyBody(
        EmailProofInstance memory instance,
        bytes[] memory proofs,
        uint proofIdx
    ) private view returns (uint) {
        // uint proofIdx = _proofIdx;
        VerifierBase regexBodyHashVerifierBase = VerifierBase(
            regexBodyHashVerifier
        );
        uint256[] memory regexBodyHashVerifierIns = new uint256[](3);
        regexBodyHashVerifierIns[0] = instance.headerBytesCommit;
        regexBodyHashVerifierIns[1] = instance.bodyhashMaskedCharsCommit;
        regexBodyHashVerifierIns[2] = instance.bodyhashSubstrIdsCommit;
        require(
            regexBodyHashVerifierBase.verify(
                regexBodyHashVerifierIns,
                proofs[proofIdx]
            ),
            "invalid regexBodyHashVerifier proof"
        );
        proofIdx += 1;
        VerifierBase charsShiftBodyHashVerifierBase = VerifierBase(
            charsShiftBodyHashVerifier
        );
        uint256[] memory charsShiftBodyHashVerifierIns = new uint256[](3);
        charsShiftBodyHashVerifierIns[0] = instance.bodyhashMaskedCharsCommit;
        charsShiftBodyHashVerifierIns[1] = instance.bodyhashSubstrIdsCommit;
        charsShiftBodyHashVerifierIns[2] = instance.bodyhashBase64Commit;
        require(
            charsShiftBodyHashVerifierBase.verify(
                charsShiftBodyHashVerifierIns,
                proofs[proofIdx]
            ),
            "invalid charsShiftBodyHashVerifier proof"
        );
        proofIdx += 1;
        VerifierBase sha256BodyVerifierBase = VerifierBase(sha256BodyVerifier);
        uint256[] memory sha256BodyVerifierIns = new uint256[](2);
        sha256BodyVerifierIns[0] = instance.bodyBytesCommit;
        sha256BodyVerifierIns[1] = instance.bodyhashCommit;
        require(
            sha256BodyVerifierBase.verify(
                sha256BodyVerifierIns,
                proofs[proofIdx]
            ),
            "invalid sha256BodyVerifier proof"
        );
        proofIdx += 1;
        VerifierBase base64VerifierBase = VerifierBase(base64Verifier);
        uint256[] memory base64VerifierIns = new uint256[](2);
        base64VerifierIns[0] = instance.bodyhashCommit;
        base64VerifierIns[1] = instance.bodyhashBase64Commit;
        require(
            base64VerifierBase.verify(base64VerifierIns, proofs[proofIdx]),
            "invalid base64Verifier proof"
        );
        proofIdx += 1;
        VerifierBase regexBodyVerifierBase = VerifierBase(regexBodyVerifier);
        uint256[] memory regexBodyVerifierIns = new uint256[](3);
        regexBodyVerifierIns[0] = instance.bodyBytesCommit;
        regexBodyVerifierIns[1] = instance.bodyMaskedCharsCommit;
        regexBodyVerifierIns[2] = instance.bodySubstrIdsCommit;
        require(
            regexBodyVerifierBase.verify(
                regexBodyVerifierIns,
                proofs[proofIdx]
            ),
            "invalid regexBodyVerifier proof"
        );
        proofIdx += 1;
        if (bodyExposeSubstrs) {
            proofIdx = verifyBodySubstrs(instance, proofs, proofIdx);
        }
        return proofIdx;
    }

    function verifyBodySubstrs(
        EmailProofInstance memory instance,
        bytes[] memory proofs,
        uint _proofIdx
    ) private view returns (uint) {
        uint proofIdx = _proofIdx;
        bytes memory expectedBodyMaskedChars = new bytes(maxBodyBytes);
        bytes memory expectedBodySubstrIds = new bytes(maxBodyBytes);
        for (uint i = 0; i < instance.bodySubstrs.length; i++) {
            uint startIdx = instance.bodySubstrIdxes[i];
            for (uint j = 0; j < bytes(instance.bodySubstrs[i]).length; j++) {
                expectedBodyMaskedChars[startIdx + j] = bytes(
                    instance.bodySubstrs[i]
                )[j];
                expectedBodySubstrIds[startIdx + j] = bytes1(uint8(i + 1));
            }
        }
        VerifierBase sha256BodyMaskedCharsVerifierBase = VerifierBase(
            sha256BodyMaskedCharsVerifier
        );
        uint256[] memory sha256BodyMaskedCharsVerifierIns = new uint256[](3);
        sha256BodyMaskedCharsVerifierIns[0] = instance.bodyMaskedCharsCommit;
        bytes32 sha256Hash = sha256(expectedBodyMaskedChars);
        uint coeff = 1;
        for (uint i = 0; i < 31; i++) {
            sha256BodyMaskedCharsVerifierIns[1] += (coeff *
                uint(uint8(sha256Hash[i])));
            coeff = coeff << 8;
        }
        sha256BodyMaskedCharsVerifierIns[2] = uint(uint8(sha256Hash[31]));
        require(
            sha256BodyMaskedCharsVerifierBase.verify(
                sha256BodyMaskedCharsVerifierIns,
                proofs[proofIdx]
            ),
            "invalid sha256BodyMaskedCharsVerifier proof"
        );
        proofIdx += 1;
        VerifierBase sha256BodySubstrIdsVerifierBase = VerifierBase(
            sha256BodySubstrIdsVerifier
        );
        uint256[] memory sha256BodySubstrIdsVerifierIns = new uint256[](3);
        sha256BodySubstrIdsVerifierIns[0] = instance.bodySubstrIdsCommit;
        sha256Hash = sha256(expectedBodySubstrIds);
        coeff = 1;
        for (uint i = 0; i < 31; i++) {
            sha256BodySubstrIdsVerifierIns[1] += (coeff *
                uint(uint8(sha256Hash[i])));
            coeff = coeff << 8;
        }
        sha256BodySubstrIdsVerifierIns[2] = uint(uint8(sha256Hash[31]));
        require(
            sha256BodySubstrIdsVerifierBase.verify(
                sha256BodySubstrIdsVerifierIns,
                proofs[proofIdx]
            ),
            "invalid sha256BodySubstrIdsVerifier proof"
        );
        proofIdx += 1;
        return proofIdx;
    }
}
