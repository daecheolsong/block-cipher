package com.example.blockcipher.core;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES 단일 블록 연산 구현체입니다.
 *
 * <p>주의: 여기서 사용하는 {@code AES/ECB/NoPadding}은
 * "운영 모드 ECB를 쓰겠다"는 뜻이 아니라, 블록 암호 원시함수 {@code E_k}/{@code D_k}
 * 를 얻기 위한 JCA 엔진 설정입니다.
 * 실제 운영 모드(ECB/CBC/CFB/OFB/CTR) 규칙은 상위 {@code mode} 패키지에서 구현합니다.</p>
 */
public final class AesBlockCipher implements BlockCipher {
    /** AES 고정 블록 크기 = 16바이트(128비트). */
    public static final int AES_BLOCK_SIZE = 16;

    private final SecretKeySpec secretKey;

    /**
     * AES 키를 초기화합니다.
     *
     * @param key 16/24/32바이트(AES-128/192/256) 키
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

    @Override
    public byte[] encryptBlock(byte[] plaintextBlock) {
        return runCipher(plaintextBlock, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] decryptBlock(byte[] ciphertextBlock) {
        return runCipher(ciphertextBlock, Cipher.DECRYPT_MODE);
    }

    /**
     * 내부 공통 단일 블록 연산입니다.
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
