package com.example.blockcipher.mode;

/**
 * 블록 암호 운영 모드 공통 인터페이스입니다.
 *
 * <p>입력/출력 길이 규칙:
 * <ul>
 *   <li>ECB/CBC: 내부적으로 PKCS#7 패딩을 적용하므로 평문 길이 제약이 없습니다.</li>
 *   <li>CFB/OFB/CTR: 스트림처럼 동작하여 임의 길이를 처리합니다.</li>
 * </ul>
 * </p>
 */
public interface ModeOfOperation {
    /** 모드 식별자(ECB/CBC/CFB/OFB/CTR). */
    ModeType type();

    /**
     * 필요한 IV/nonce 길이(바이트). ECB는 0을 반환합니다.
     */
    int ivLength();

    /**
     * 평문을 암호화합니다.
     *
     * @param plaintext 입력 평문
     * @param ivOrNonce 모드별 IV/nonce (ECB는 빈 배열 또는 null)
     * @return 암호문
     */
    byte[] encrypt(byte[] plaintext, byte[] ivOrNonce);

    /**
     * 암호문을 복호화합니다.
     *
     * @param ciphertext 입력 암호문
     * @param ivOrNonce 모드별 IV/nonce (ECB는 빈 배열 또는 null)
     * @return 평문
     */
    byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce);
}
