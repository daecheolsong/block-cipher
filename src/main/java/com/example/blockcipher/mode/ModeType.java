package com.example.blockcipher.mode;

/**
 * 지원하는 블록 암호 운영 모드 목록입니다.
 */
public enum ModeType {
    /** Electronic Codebook */
    ECB,
    /** Cipher Block Chaining */
    CBC,
    /** Cipher Feedback (본 구현은 full-block CFB) */
    CFB,
    /** Output Feedback */
    OFB,
    /** Counter */
    CTR
}
