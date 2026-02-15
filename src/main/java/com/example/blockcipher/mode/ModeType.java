package com.example.blockcipher.mode;

/**
 * 프로젝트에서 지원하는 블록 암호 운영 모드 목록입니다.
 */
public enum ModeType {
    /** ECB(전자 코드북 모드) */
    ECB,
    /** CBC(암호문 블록 연쇄 모드) */
    CBC,
    /** CFB(암호문 피드백 모드, 본 구현은 블록 단위 CFB) */
    CFB,
    /** OFB(출력 피드백 모드) */
    OFB,
    /** CTR(카운터 모드) */
    CTR
}
