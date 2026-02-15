package com.example.blockcipher.service;

import com.example.blockcipher.mode.ModeOfOperation;
import com.example.blockcipher.util.Bytes;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 모드 사용 편의를 위한 서비스 계층입니다.
 *
 * <p>암호화 결과 포맷을 {@code [IV(or nonce) || ciphertext]}로 통일합니다.
 * ECB처럼 IV가 없는 모드는 헤더 길이가 0입니다.</p>
 */
public final class ModeCipherService {
    private final ModeOfOperation mode;
    private final SecureRandom random;

    /**
     * @param mode 사용할 운영 모드 구현체
     */
    public ModeCipherService(ModeOfOperation mode) {
        this.mode = mode;
        this.random = new SecureRandom();
    }

    /**
     * 랜덤 IV/nonce를 생성해 암호화하고, 결과를 {@code [IV||C]} 형태로 반환합니다.
     */
    public byte[] encryptWithHeader(byte[] plaintext) {
        int ivLength = mode.ivLength();
        byte[] iv = new byte[ivLength];
        if (ivLength > 0) {
            random.nextBytes(iv);
        }
        byte[] ciphertext = mode.encrypt(plaintext, iv);
        return Bytes.concat(iv, ciphertext);
    }

    /**
     * {@code [IV||C]} 입력에서 헤더를 분리해 복호화합니다.
     */
    public byte[] decryptWithHeader(byte[] ivAndCiphertext) {
        int ivLength = mode.ivLength();
        if (ivAndCiphertext.length < ivLength) {
            throw new IllegalArgumentException("input is too short");
        }
        byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, ivLength);
        byte[] ciphertext = Arrays.copyOfRange(ivAndCiphertext, ivLength, ivAndCiphertext.length);
        return mode.decrypt(ciphertext, iv);
    }
}
