package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;
import com.example.blockcipher.util.Bytes;
import java.util.Arrays;

/**
 * OFB 모드 구현입니다.
 *
 * <p>{@code I_1 = IV}</p>
 * <p>{@code O_i = E_k(I_i)}</p>
 * <p>{@code I_{i+1} = O_i}</p>
 * <p>{@code C_i = P_i xor O_i}</p>
 * <p>{@code P_i = C_i xor O_i}</p>
 *
 * <p>암호화/복호화 모두 같은 keystream XOR 함수를 사용합니다.</p>
 */
public final class OFBMode extends AbstractMode {
    /**
     * @param cipher 단일 블록 암호 함수
     */
    public OFBMode(BlockCipher cipher) {
        super(cipher);
    }

    @Override
    public ModeType type() {
        return ModeType.OFB;
    }

    /**
     * OFB 암호화를 수행합니다.
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        return applyKeystream(plaintext, ivOrNonce);
    }

    /**
     * OFB 복호화를 수행합니다.
     *
     * <p>암호화와 동일한 함수로 처리됩니다.</p>
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        return applyKeystream(ciphertext, ivOrNonce);
    }

    /**
     * 입력 데이터에 OFB keystream을 XOR하는 공통 함수입니다.
     *
     * <p>각 청크마다</p>
     * <p>1. feedback을 암호화해서 다음 keystream 블록 생성</p>
     * <p>2. 입력 청크와 XOR</p>
     */
    private byte[] applyKeystream(byte[] input, byte[] ivOrNonce) {
        int blockSize = cipher.blockSize();
        byte[][] feedback = {Arrays.copyOf(ivOrNonce, ivOrNonce.length)};

        return mapChunks(input, blockSize, (chunk, chunkIndex) -> {
            // 이전 내부 상태를 암호화해 다음 keystream 블록을 생성합니다.
            feedback[0] = cipher.encryptBlock(feedback[0]);
            byte[] streamChunk = Bytes.slice(feedback[0], 0, chunk.length);
            // 입력과 keystream을 XOR하면 암호화/복호화 결과가 됩니다.
            return Bytes.xor(chunk, streamChunk);
        });
    }
}
