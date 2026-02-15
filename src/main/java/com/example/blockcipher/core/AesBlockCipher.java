package com.example.blockcipher.core;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES를 단일 블록 연산 형태로 감싼 구현체입니다.
 *
 * <p>중요한 점은 {@code AES/ECB/NoPadding} 설정이 "운영 모드로 ECB를 쓰겠다"는 의미가 아니라,
 * JCA에서 블록 암호 원시 함수 {@code E_k(·)} / {@code D_k(·)}를 얻기 위한 내부 설정이라는 점입니다.
 * 운영 모드(ECB/CBC/CFB/OFB/CTR)의 체이닝 규칙은 mode 패키지에서 별도로 수행합니다.</p>
 */
public final class AesBlockCipher implements BlockCipher {
    /** AES는 항상 16바이트 블록을 사용합니다. */
    public static final int AES_BLOCK_SIZE = 16;

    /** 복사 보관된 비밀키 객체입니다. */
    private final SecretKeySpec secretKey;

    /**
     * AES 키로 객체를 생성합니다.
     *
     * @param key 16/24/32바이트 키(AES-128/192/256)
     */
    public AesBlockCipher(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("AES key must be 16, 24, or 32 bytes");
        }
        this.secretKey = new SecretKeySpec(Arrays.copyOf(key, key.length), "AES");
    }

    @Override
    public int blockSize() {
        return AES_BLOCK_SIZE;
    }

    /**
     * 한 블록을 AES로 암호화합니다.
     */
    @Override
    public byte[] encryptBlock(byte[] plaintextBlock) {
        return runCipher(plaintextBlock, Cipher.ENCRYPT_MODE);
    }

    /**
     * 한 블록을 AES로 복호화합니다.
     */
    @Override
    public byte[] decryptBlock(byte[] ciphertextBlock) {
        return runCipher(ciphertextBlock, Cipher.DECRYPT_MODE);
    }

    /**
     * 공통 블록 연산 함수입니다.
     *
     * <p>입력 길이를 검증한 뒤 JCA Cipher를 생성/초기화/실행합니다.
     * 보안 예외는 프로젝트 전용 {@link CryptoException}으로 감싸서 상위에서 일관되게 처리하게 합니다.</p>
     */
    private byte[] runCipher(byte[] input, int mode) {
        if (input == null || input.length != AES_BLOCK_SIZE) {
            throw new IllegalArgumentException("input must be exactly one AES block (16 bytes)");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(mode, secretKey);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES block operation failed", e);
        }
    }
}
