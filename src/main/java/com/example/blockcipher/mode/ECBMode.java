package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;
import com.example.blockcipher.padding.PaddingScheme;
import com.example.blockcipher.util.Bytes;

/**
 * ECB(Electronic Codebook) 모드 구현입니다.
 *
 * <p>NIST SP 800-38A, Section 6.1의 정의:
 * <pre>
 * C_j = E_k(P_j),  j = 1..n
 * P_j = D_k(C_j),  j = 1..n
 * </pre>
 * 각 블록이 독립적으로 처리되므로 동일한 평문 블록은 동일한 암호문 블록을 만듭니다.
 * 본 구현은 실습 편의를 위해 PKCS#7 패딩을 적용합니다.</p>
 */
public final class ECBMode extends AbstractMode {
    private final PaddingScheme padding;

    /**
     * @param cipher 단일 블록 암호 원시함수
     * @param padding 패딩 스킴(PKCS#7 권장)
     */
    public ECBMode(BlockCipher cipher, PaddingScheme padding) {
        super(cipher);
        this.padding = padding;
    }

    @Override
    public ModeType type() {
        return ModeType.ECB;
    }

    @Override
    public int ivLength() {
        return 0;
    }

    /**
     * ECB는 IV/nonce를 사용하지 않습니다.
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] ivOrNonce) {
        if (ivOrNonce != null && ivOrNonce.length > 0) {
            throw new IllegalArgumentException("ECB does not use IV/nonce");
        }
        byte[] padded = padding.pad(plaintext, cipher.blockSize());
        byte[] out = new byte[padded.length];
        int blockSize = cipher.blockSize();
        for (int offset = 0; offset < padded.length; offset += blockSize) {
            byte[] block = Bytes.slice(padded, offset, blockSize);
            byte[] encrypted = cipher.encryptBlock(block);
            System.arraycopy(encrypted, 0, out, offset, blockSize);
        }
        return out;
    }

    /**
     * ECB는 IV/nonce를 사용하지 않습니다.
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce) {
        if (ivOrNonce != null && ivOrNonce.length > 0) {
            throw new IllegalArgumentException("ECB does not use IV/nonce");
        }
        requireMultipleBlockLength(ciphertext);
        byte[] out = new byte[ciphertext.length];
        int blockSize = cipher.blockSize();
        for (int offset = 0; offset < ciphertext.length; offset += blockSize) {
            byte[] block = Bytes.slice(ciphertext, offset, blockSize);
            byte[] decrypted = cipher.decryptBlock(block);
            System.arraycopy(decrypted, 0, out, offset, blockSize);
        }
        return padding.unpad(out, blockSize);
    }
}
