package com.example.blockcipher.service;

import com.example.blockcipher.mode.ModeOfOperation;
import com.example.blockcipher.util.Bytes;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 운영 모드 사용을 단순화하는 서비스 클래스입니다.
 *
 * <p>암호화 결과를 항상 {@code [IV(or nonce) || ciphertext]} 형식으로 맞춰서 반환하고,
 * 복호화 시에는 같은 형식을 역으로 분해해 모드에 전달합니다.</p>
 */
public final class ModeCipherService {
    /** 실제 암복호화를 수행할 모드 구현체. */
    private final ModeOfOperation mode;

    /** IV/nonce 생성을 위한 난수기. */
    private final SecureRandom random;

    /**
     * @param mode 사용할 모드 구현체
     */
    public ModeCipherService(ModeOfOperation mode) {
        this.mode = mode;
        this.random = new SecureRandom();
    }

    /**
     * 평문을 암호화하고 헤더(IV/nonce)를 앞에 붙여 반환합니다.
     *
     * <p>처리 순서</p>
     * <p>1. 모드가 요구하는 IV 길이 조회</p>
     * <p>2. 해당 길이만큼 난수 IV 생성(ECB는 0길이)</p>
     * <p>3. 모드 암호화 수행</p>
     * <p>4. {@code [IV || ciphertext]}로 결합해 반환</p>
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
     * {@code [IV || ciphertext]} 형식 입력을 복호화합니다.
     *
     * <p>처리 순서</p>
     * <p>1. 앞부분 IV를 분리</p>
     * <p>2. 나머지 암호문 분리</p>
     * <p>3. 모드 복호화 호출</p>
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
