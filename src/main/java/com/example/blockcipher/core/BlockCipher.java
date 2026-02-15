package com.example.blockcipher.core;

/**
 * 블록 암호의 가장 기본 연산을 정의하는 인터페이스입니다.
 *
 * <p>이 인터페이스는 "운영 모드"를 모르고, 오직 한 블록 길이의 데이터만 처리합니다.
 * CBC/CFB/CTR 같은 모드 규칙은 이 인터페이스를 호출하는 상위 계층에서 구현합니다.</p>
 */
public interface BlockCipher {
    /**
     * 블록 크기를 바이트 단위로 반환합니다.
     *
     * <p>AES는 항상 16바이트(128비트) 블록을 사용합니다.</p>
     */
    int blockSize();

    /**
     * 한 개의 평문 블록을 암호화합니다.
     *
     * @param plaintextBlock 정확히 {@link #blockSize()} 길이의 평문 블록
     * @return 암호화된 블록
     */
    byte[] encryptBlock(byte[] plaintextBlock);

    /**
     * 한 개의 암호문 블록을 복호화합니다.
     *
     * @param ciphertextBlock 정확히 {@link #blockSize()} 길이의 암호문 블록
     * @return 복호화된 블록
     */
    byte[] decryptBlock(byte[] ciphertextBlock);
}
