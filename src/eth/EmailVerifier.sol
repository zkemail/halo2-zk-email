// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
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

    constructor(
        address _sha256HeaderVerifier,
        address _signVerifyVerifier,
        address _regexHeaderVerifier,
        address _sha256HeaderMaskedCharsVerifier,
        address _sha256HeaderSubstrIdsVerifier,
        address _regexBodyHashVerifier,
        address _charsShiftBodyHashVerifier,
        address _sha256BodyVerifier,
        address _base64Verifier,
        address _regexBodyVerifier,
        address _sha256BodyMaskedCharsVerifier,
        address _sha256BodySubstrIdsVerifier,
        bool _headerExposeSubstrs,
        bool _bodyEnable,
        bool _bodyExposeSubstrs,
        uint _maxHeaderBytes,
        uint _maxBodyBytes
    ) {
        sha256HeaderVerifier = _sha256HeaderVerifier;
        signVerifyVerifier = _signVerifyVerifier;
        regexHeaderVerifier = _regexHeaderVerifier;
        sha256HeaderMaskedCharsVerifier = _sha256HeaderMaskedCharsVerifier;
        sha256HeaderSubstrIdsVerifier = _sha256HeaderSubstrIdsVerifier;
        regexBodyHashVerifier = _regexBodyHashVerifier;
        charsShiftBodyHashVerifier = _charsShiftBodyHashVerifier;
        sha256BodyVerifier = _sha256BodyVerifier;
        base64Verifier = _base64Verifier;
        regexBodyVerifier = _regexBodyVerifier;
        sha256BodyMaskedCharsVerifier = _sha256BodyMaskedCharsVerifier;
        sha256BodySubstrIdsVerifier = _sha256BodySubstrIdsVerifier;
        headerExposeSubstrs = _headerExposeSubstrs;
        bodyEnable = _bodyEnable;
        bodyExposeSubstrs = _bodyExposeSubstrs;
        maxHeaderBytes = _maxHeaderBytes;
        maxBodyBytes = _maxBodyBytes;
    }

    function verify(
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
            )
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
            )
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
            )
        );
        proofIdx++;
        if (headerExposeSubstrs) {
            bytes memory expectedHeaderMaskedChars = new bytes(maxHeaderBytes);
            bytes memory expectedHeaderSubstrIds = new bytes(maxHeaderBytes);
            for (uint i = 0; i < instance.headerSubstrs.length; i++) {
                uint startIdx = instance.headerSubstrIdxes[i];
                for (
                    uint j = 0;
                    j < bytes(instance.headerSubstrs[i]).length;
                    j++
                ) {
                    expectedHeaderMaskedChars[startIdx + j] = bytes(
                        instance.headerSubstrs[i]
                    )[j];
                    expectedHeaderSubstrIds[startIdx + j] = bytes1(
                        uint8(i + 1)
                    );
                }
            }
            VerifierBase sha256HeaderMaskedCharsVerifierBase = VerifierBase(
                sha256HeaderMaskedCharsVerifier
            );
            uint256[] memory sha256HeaderMaskedCharsVerifierIns = new uint256[](
                2
            );
            sha256HeaderMaskedCharsVerifierIns[0] = instance
                .headerMaskedCharsCommit;
            sha256HeaderMaskedCharsVerifierIns[1] = uint256(
                sha256(expectedHeaderMaskedChars)
            );
            require(
                sha256HeaderMaskedCharsVerifierBase.verify(
                    sha256HeaderMaskedCharsVerifierIns,
                    proofs[proofIdx]
                )
            );
            proofIdx++;
            VerifierBase sha256HeaderSubstrIdsVerifierBase = VerifierBase(
                sha256HeaderSubstrIdsVerifier
            );
            uint256[] memory sha256HeaderSubstrIdsVerifierIns = new uint256[](
                2
            );
            sha256HeaderSubstrIdsVerifierIns[0] = instance
                .headerSubstrIdsCommit;
            sha256HeaderSubstrIdsVerifierIns[1] = uint256(
                sha256(expectedHeaderSubstrIds)
            );
            require(
                sha256HeaderSubstrIdsVerifierBase.verify(
                    sha256HeaderSubstrIdsVerifierIns,
                    proofs[proofIdx]
                )
            );
            proofIdx++;
        }
        if (bodyEnable) {
            VerifierBase regexBodyHashVerifierBase = VerifierBase(
                regexBodyHashVerifier
            );
            uint256[] memory regexBodyHashVerifierIns = new uint256[](3);
            regexBodyHashVerifierIns[0] = instance.bodyBytesCommit;
            regexBodyHashVerifierIns[1] = instance.bodyhashMaskedCharsCommit;
            regexBodyHashVerifierIns[2] = instance.bodyhashSubstrIdsCommit;
            require(
                regexBodyHashVerifierBase.verify(
                    regexBodyHashVerifierIns,
                    proofs[proofIdx]
                )
            );
            proofIdx++;
            VerifierBase charsShiftBodyHashVerifierBase = VerifierBase(
                charsShiftBodyHashVerifier
            );
            uint256[] memory charsShiftBodyHashVerifierIns = new uint256[](2);
            charsShiftBodyHashVerifierIns[0] = instance
                .bodyhashMaskedCharsCommit;
            charsShiftBodyHashVerifierIns[1] = instance.bodyhashBase64Commit;
            require(
                charsShiftBodyHashVerifierBase.verify(
                    charsShiftBodyHashVerifierIns,
                    proofs[proofIdx]
                )
            );
            proofIdx++;
            VerifierBase sha256BodyVerifierBase = VerifierBase(
                sha256BodyVerifier
            );
            uint256[] memory sha256BodyVerifierIns = new uint256[](2);
            sha256BodyVerifierIns[0] = instance.bodyBytesCommit;
            sha256BodyVerifierIns[1] = instance.bodyhashCommit;
            require(
                sha256BodyVerifierBase.verify(
                    sha256BodyVerifierIns,
                    proofs[proofIdx]
                )
            );
            proofIdx++;
            VerifierBase base64VerifierBase = VerifierBase(base64Verifier);
            uint256[] memory base64VerifierIns = new uint256[](2);
            base64VerifierIns[0] = instance.bodyhashCommit;
            base64VerifierIns[1] = instance.bodyhashBase64Commit;
            require(
                base64VerifierBase.verify(base64VerifierIns, proofs[proofIdx])
            );
            proofIdx++;
            VerifierBase regexBodyVerifierBase = VerifierBase(
                regexBodyVerifier
            );
            uint256[] memory regexBodyVerifierIns = new uint256[](3);
            regexBodyVerifierIns[0] = instance.bodyBytesCommit;
            regexBodyVerifierIns[1] = instance.bodyMaskedCharsCommit;
            regexBodyVerifierIns[2] = instance.bodySubstrIdsCommit;
            require(
                regexBodyVerifierBase.verify(
                    regexBodyVerifierIns,
                    proofs[proofIdx]
                )
            );
            proofIdx++;
            if (bodyExposeSubstrs) {
                bytes memory expectedBodyMaskedChars = new bytes(maxBodyBytes);
                bytes memory expectedBodySubstrIds = new bytes(maxBodyBytes);
                for (uint i = 0; i < instance.bodySubstrs.length; i++) {
                    uint startIdx = instance.bodySubstrIdxes[i];
                    for (
                        uint j = 0;
                        j < bytes(instance.bodySubstrs[i]).length;
                        j++
                    ) {
                        expectedBodyMaskedChars[startIdx + j] = bytes(
                            instance.bodySubstrs[i]
                        )[j];
                        expectedBodySubstrIds[startIdx + j] = bytes1(
                            uint8(i + 1)
                        );
                    }
                }
                VerifierBase sha256BodyMaskedCharsVerifierBase = VerifierBase(
                    sha256BodyMaskedCharsVerifier
                );
                uint256[]
                    memory sha256BodyMaskedCharsVerifierIns = new uint256[](2);
                sha256BodyMaskedCharsVerifierIns[0] = instance
                    .bodyMaskedCharsCommit;
                sha256BodyMaskedCharsVerifierIns[1] = uint256(
                    sha256(expectedBodyMaskedChars)
                );
                require(
                    sha256BodyMaskedCharsVerifierBase.verify(
                        sha256BodyMaskedCharsVerifierIns,
                        proofs[proofIdx]
                    )
                );
                proofIdx++;
                VerifierBase sha256BodySubstrIdsVerifierBase = VerifierBase(
                    sha256BodySubstrIdsVerifier
                );
                uint256[] memory sha256BodySubstrIdsVerifierIns = new uint256[](
                    2
                );
                sha256BodySubstrIdsVerifierIns[0] = instance
                    .bodySubstrIdsCommit;
                sha256BodySubstrIdsVerifierIns[1] = uint256(
                    sha256(expectedBodySubstrIds)
                );
                require(
                    sha256BodySubstrIdsVerifierBase.verify(
                        sha256BodySubstrIdsVerifierIns,
                        proofs[proofIdx]
                    )
                );
                proofIdx++;
            }
        }
    }
}
