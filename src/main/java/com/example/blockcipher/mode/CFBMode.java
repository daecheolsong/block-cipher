package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;
import com.example.blockcipher.util.Bytes;
import java.util.Arrays;

/**
 * CFB(Cipher Feedback) 모드 구현입니다.
 *
 * <p>NIST SP 800-38A, Section 6.3의 일반식(세그먼트 크기 s):
 * <pre>
 * I_1 = IV
 * I_j = LSB_{b-s}(I_{j-1}) || C_{j-1}
 * O_j = E_k(I_j)
 * C_j = P_j xor MSB_s(O_j)
 * P_j = C_j xor MSB_s(O_j)
 * </pre>
 *
 * 본 구현은 full-block CFB(s=b)만 사용하므로 단순화하면:
 * <pre>
 * O_j = E_k(C_{j-1}),   C_0 = IV
 * C_j = P_j xor O_j
 * P_j = C_j xor O_j
 * </pre>
 * 복호화에서도 블록 암호의 decrypt가 아니라 encrypt를 사용한다는 점이 핵심입니다.</p>
 */
public final class CFBMode extends AbstractMode {
    /**
     * @param cipher 단일 블록 암호 원시함수
     */
    public CFBMode(BlockCipher cipher) {
        super(cipher);
    }

    @Override
    public ModeType type() {
        return ModeType.CFB;
    }

    /**
     * CFB 암호화(스트림 유사 동작).
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        int blockSize = cipher.blockSize();
        byte[] out = new byte[plaintext.length];
        byte[] feedback = Arrays.copyOf(ivOrNonce, ivOrNonce.length);

        for (int offset = 0; offset < plaintext.length; offset += blockSize) {
            byte[] stream = cipher.encryptBlock(feedback);
            int chunk = Math.min(blockSize, plaintext.length - offset);
            for (int i = 0; i < chunk; i++) {
                out[offset + i] = (byte) (plaintext[offset + i] ^ stream[i]);
            }
            if (chunk == blockSize) {
                feedback = Bytes.slice(out, offset, blockSize);
            }
        }
        return out;
    }

    /**
     * CFB 복호화(keystream 생성은 encryptBlock 사용).
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        int blockSize = cipher.blockSize();
        byte[] out = new byte[ciphertext.length];
        byte[] feedback = Arrays.copyOf(ivOrNonce, ivOrNonce.length);

        for (int offset = 0; offset < ciphertext.length; offset += blockSize) {
            byte[] stream = cipher.encryptBlock(feedback);
            int chunk = Math.min(blockSize, ciphertext.length - offset);
            for (int i = 0; i < chunk; i++) {
                out[offset + i] = (byte) (ciphertext[offset + i] ^ stream[i]);
            }
            if (chunk == blockSize) {
                feedback = Bytes.slice(ciphertext, offset, blockSize);
            }
        }
        return out;
    }
}
