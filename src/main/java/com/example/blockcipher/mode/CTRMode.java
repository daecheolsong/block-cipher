package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;
import com.example.blockcipher.util.Bytes;
import java.util.Arrays;

/**
 * CTR(Counter) 모드 구현입니다.
 *
 * <p>NIST SP 800-38A, Section 6.5의 정의:
 * <pre>
 * O_j = E_k(T_j)
 * C_j = P_j xor O_j
 * P_j = C_j xor O_j
 * </pre>
 * 여기서 {@code T_j}는 증가하는 counter block입니다.
 *
 * <p>핵심 보안 조건(동일 표준 부록 B):
 * 같은 키에 대해 모든 counter block(T_j)은 절대 재사용되면 안 됩니다.
 * 재사용 시 keystream이 같아져 {@code C1 xor C2 = P1 xor P2} 누출이 발생합니다.</p>
 */
public final class CTRMode extends AbstractMode {
    /**
     * @param cipher 단일 블록 암호 원시함수
     */
    public CTRMode(BlockCipher cipher) {
        super(cipher);
    }

    @Override
    public ModeType type() {
        return ModeType.CTR;
    }

    /**
     * CTR 암호화(복호화와 동일한 keystream XOR 변환).
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        return applyKeystream(plaintext, ivOrNonce);
    }

    /**
     * CTR 복호화(암호화와 동일한 keystream XOR 변환).
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        return applyKeystream(ciphertext, ivOrNonce);
    }

    /**
     * 입력 길이만큼 counter block을 증가시키며 keystream을 적용합니다.
     * counter가 wrap되고 처리할 입력이 남아 있으면 즉시 예외를 던집니다.
     */
    private byte[] applyKeystream(byte[] input, byte[] ivOrNonce) {
        int blockSize = cipher.blockSize();
        byte[] out = new byte[input.length];
        byte[] counter = Arrays.copyOf(ivOrNonce, ivOrNonce.length);

        for (int offset = 0; offset < input.length; offset += blockSize) {
            byte[] stream = cipher.encryptBlock(counter);
            int chunk = Math.min(blockSize, input.length - offset);
            for (int i = 0; i < chunk; i++) {
                out[offset + i] = (byte) (input[offset + i] ^ stream[i]);
            }
            boolean wrapped = Bytes.incrementBigEndian(counter);
            if (wrapped && offset + chunk < input.length) {
                throw new IllegalStateException("CTR counter wrapped; nonce/counter space exhausted");
            }
        }
        return out;
    }
}
