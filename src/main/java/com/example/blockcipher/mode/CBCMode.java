package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;
import com.example.blockcipher.padding.PaddingScheme;
import com.example.blockcipher.util.Bytes;
import java.util.Arrays;

/**
 * CBC(Cipher Block Chaining) 모드 구현입니다.
 *
 * <p>NIST SP 800-38A, Section 6.2의 정의:
 * <pre>
 * C_1 = E_k(P_1 xor IV)
 * C_j = E_k(P_j xor C_{j-1}),  j = 2..n
 *
 * P_1 = D_k(C_1) xor IV
 * P_j = D_k(C_j) xor C_{j-1},  j = 2..n
 * </pre>
 *
 * 본 구현은 평문 입력 시 PKCS#7 패딩을 적용합니다.
 * 또한 CBC/CFB에서는 IV가 예측 가능하면 위험하므로, IV는 충분한 난수로 생성해야 합니다.</p>
 */
public final class CBCMode extends AbstractMode {
    private final PaddingScheme padding;

    /**
     * @param cipher 단일 블록 암호 원시함수
     * @param padding 패딩 스킴(PKCS#7 권장)
     */
    public CBCMode(BlockCipher cipher, PaddingScheme padding) {
        super(cipher);
        this.padding = padding;
    }

    @Override
    public ModeType type() {
        return ModeType.CBC;
    }

    /**
     * CBC 암호화:
     * {@code P_i xor C_{i-1}}를 만든 뒤 블록 암호화합니다.
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        byte[] padded = padding.pad(plaintext, cipher.blockSize());
        byte[] out = new byte[padded.length];
        byte[] previous = Arrays.copyOf(ivOrNonce, ivOrNonce.length);
        int blockSize = cipher.blockSize();

        for (int offset = 0; offset < padded.length; offset += blockSize) {
            byte[] block = Bytes.slice(padded, offset, blockSize);
            byte[] xored = Bytes.xor(block, previous);
            byte[] encrypted = cipher.encryptBlock(xored);
            System.arraycopy(encrypted, 0, out, offset, blockSize);
            previous = encrypted;
        }
        return out;
    }

    /**
     * CBC 복호화:
     * {@code D_k(C_i) xor C_{i-1}}를 계산합니다.
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        requireMultipleBlockLength(ciphertext);
        byte[] out = new byte[ciphertext.length];
        byte[] previous = Arrays.copyOf(ivOrNonce, ivOrNonce.length);
        int blockSize = cipher.blockSize();

        for (int offset = 0; offset < ciphertext.length; offset += blockSize) {
            byte[] currentCipher = Bytes.slice(ciphertext, offset, blockSize);
            byte[] decrypted = cipher.decryptBlock(currentCipher);
            byte[] plainBlock = Bytes.xor(decrypted, previous);
            System.arraycopy(plainBlock, 0, out, offset, blockSize);
            previous = currentCipher;
        }
        return padding.unpad(out, blockSize);
    }
}
