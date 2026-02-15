package com.example.blockcipher.core;

/**
 * 블록 암호의 "단일 블록 원시 연산"을 추상화한 인터페이스입니다.
 *
 * <p>모드(ECB/CBC/CFB/OFB/CTR)는 이 인터페이스를 이용해
 * {@code E_k(·)} / {@code D_k(·)} 연산을 조합합니다.
 * 즉, 이 계층은 모드 체이닝 규칙을 알지 못하고,
 * 정확히 한 블록 길이 데이터만 처리합니다.</p>
 */
public interface BlockCipher {
    /**
     * 블록 크기(바이트)를 반환합니다. AES는 16바이트(128비트)입니다.
     */
    int blockSize();

    /**
     * 단일 평문 블록을 암호화합니다.
     *
     * @param plaintextBlock 블록 크기와 동일한 길이의 평문 블록
     * @return 암호문 블록
     */
    byte[] encryptBlock(byte[] plaintextBlock);

    /**
     * 단일 암호문 블록을 복호화합니다.
     *
     * @param ciphertextBlock 블록 크기와 동일한 길이의 암호문 블록
     * @return 평문 블록
     */
    byte[] decryptBlock(byte[] ciphertextBlock);
}
