package com.example.blockcipher.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.example.blockcipher.core.AesBlockCipher;
import com.example.blockcipher.padding.Pkcs7Padding;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * ECB의 패턴 노출 특성과 CBC의 체이닝 특성을 비교하는 테스트입니다.
 */
class EcbPatternLeakageTest {
    /**
     * 동일한 평문 블록은 ECB에서 동일한 암호문 블록으로 변환됩니다.
     */
    @Test
    void identicalPlainBlocksProduceIdenticalCipherBlocksInEcb() {
        byte[] key = new byte[16];
        byte[] block = new byte[16];
        Arrays.fill(block, (byte) 0x5A);

        byte[] plaintext = new byte[32];
        System.arraycopy(block, 0, plaintext, 0, 16);
        System.arraycopy(block, 0, plaintext, 16, 16);

        ECBMode ecb = new ECBMode(new AesBlockCipher(key), new Pkcs7Padding());
        byte[] ciphertext = ecb.encrypt(plaintext, new byte[0]);

        byte[] c1 = Arrays.copyOfRange(ciphertext, 0, 16);
        byte[] c2 = Arrays.copyOfRange(ciphertext, 16, 32);
        assertArrayEquals(c1, c2);
    }

    /**
     * 동일한 평문 블록이라도 CBC에서는 보통 서로 다른 암호문 블록이 생성됩니다.
     */
    @Test
    void identicalPlainBlocksDoNotMatchInCbc() {
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        byte[] block = new byte[16];
        Arrays.fill(block, (byte) 0x5A);

        byte[] plaintext = new byte[32];
        System.arraycopy(block, 0, plaintext, 0, 16);
        System.arraycopy(block, 0, plaintext, 16, 16);

        CBCMode cbc = new CBCMode(new AesBlockCipher(key), new Pkcs7Padding());
        byte[] ciphertext = cbc.encrypt(plaintext, iv);

        byte[] c1 = Arrays.copyOfRange(ciphertext, 0, 16);
        byte[] c2 = Arrays.copyOfRange(ciphertext, 16, 32);
        assertFalse(Arrays.equals(c1, c2));
    }
}
