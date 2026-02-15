package com.example.blockcipher.mode;

/**
 * 블록 암호 운영 모드의 공통 동작을 정의합니다.
 *
 * <p>모드 구현체는 다음 책임을 가집니다.</p>
 * <p>1. 필요한 IV/nonce 길이를 명확히 제공한다.</p>
 * <p>2. 모드 규칙에 맞춰 암호화/복호화를 수행한다.</p>
 * <p>3. 잘못된 입력 길이나 IV 길이를 즉시 검증한다.</p>
 */
public interface ModeOfOperation {
    /**
     * 구현체의 모드 종류를 반환합니다.
     */
    ModeType type();

    /**
     * 필요한 IV/nonce 길이를 바이트 단위로 반환합니다.
     *
     * <p>예: AES 기반 CBC/CFB/OFB/CTR는 16바이트, ECB는 0바이트.</p>
     */
    int ivLength();

    /**
     * 평문을 암호문으로 변환합니다.
     *
     * @param plaintext 입력 평문
     * @param ivOrNonce 모드에서 사용할 IV/nonce
     * @return 암호문
     */
    byte[] encrypt(byte[] plaintext, byte[] ivOrNonce);

    /**
     * 암호문을 평문으로 복원합니다.
     *
     * @param ciphertext 입력 암호문
     * @param ivOrNonce 모드에서 사용할 IV/nonce
     * @return 복호화된 평문
     */
    byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce);
}
