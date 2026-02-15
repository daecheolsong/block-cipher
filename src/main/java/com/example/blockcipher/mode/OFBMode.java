package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;
import java.util.Arrays;

/**
 * OFB(Output Feedback) 모드 구현입니다.
 *
 * <p>NIST SP 800-38A, Section 6.4의 정의:
 * <pre>
 * I_1 = IV
 * O_j = E_k(I_j)
 * I_j = O_{j-1} (j >= 2)
 * C_j = P_j xor O_j
 * P_j = C_j xor O_j
 * </pre>
 *
 * OFB는 암/복호화가 동일한 keystream XOR로 동작합니다.
 * 단, 같은 키에서 IV(초기 상태)를 재사용하면 keystream이 재사용되므로 금지해야 합니다.</p>
 */
public final class OFBMode extends AbstractMode {
    /**
     * @param cipher 단일 블록 암호 원시함수
     */
    public OFBMode(BlockCipher cipher) {
        super(cipher);
    }

    @Override
    public ModeType type() {
        return ModeType.OFB;
    }

    /**
     * OFB 암호화(keystream XOR).
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        return applyKeystream(plaintext, ivOrNonce);
    }

    /**
     * OFB 복호화(암호화와 동일 함수).
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        return applyKeystream(ciphertext, ivOrNonce);
    }

    /**
     * 내부 공통 keystream 적용 로직.
     */
    private byte[] applyKeystream(byte[] input, byte[] ivOrNonce) {
        int blockSize = cipher.blockSize();
        byte[] out = new byte[input.length];
        byte[] feedback = Arrays.copyOf(ivOrNonce, ivOrNonce.length);

        for (int offset = 0; offset < input.length; offset += blockSize) {
            feedback = cipher.encryptBlock(feedback);
            int chunk = Math.min(blockSize, input.length - offset);
            for (int i = 0; i < chunk; i++) {
                out[offset + i] = (byte) (input[offset + i] ^ feedback[i]);
            }
        }
        return out;
    }
}
