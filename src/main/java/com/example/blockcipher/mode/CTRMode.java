package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;
import com.example.blockcipher.util.Bytes;
import java.util.Arrays;

/**
 * CTR 모드 구현입니다.
 *
 * <p>{@code S_i = E_k(T_i)}</p>
 * <p>{@code C_i = P_i xor S_i}</p>
 * <p>{@code P_i = C_i xor S_i}</p>
 *
 * <p>여기서 {@code T_i}는 nonce + counter로 구성된 카운터 블록입니다.
 * 같은 키에서 같은 카운터 블록을 재사용하면 keystream이 재사용되므로 보안상 매우 위험합니다.</p>
 */
public final class CTRMode extends AbstractMode {
    /**
     * @param cipher 단일 블록 암호 함수
     */
    public CTRMode(BlockCipher cipher) {
        super(cipher);
    }

    @Override
    public ModeType type() {
        return ModeType.CTR;
    }

    /**
     * CTR 암호화를 수행합니다.
     *
     * <p>복호화와 동일한 keystream XOR 함수가 사용됩니다.</p>
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        return applyKeystream(plaintext, ivOrNonce);
    }

    /**
     * CTR 복호화를 수행합니다.
     *
     * <p>암호화와 동일한 함수를 재사용합니다.</p>
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        return applyKeystream(ciphertext, ivOrNonce);
    }

    /**
     * 입력 데이터에 CTR keystream을 XOR하는 공통 함수입니다.
     *
     * <p>각 청크마다</p>
     * <p>1. 현재 counter 블록을 암호화해서 keystream 생성</p>
     * <p>2. 입력 청크와 XOR</p>
     * <p>3. counter를 1 증가</p>
     * <p>4. wrap가 발생했는데 아직 처리할 입력이 남아 있으면 예외 발생</p>
     */
    private byte[] applyKeystream(byte[] input, byte[] ivOrNonce) {
        int blockSize = cipher.blockSize();
        byte[][] counter = {Arrays.copyOf(ivOrNonce, ivOrNonce.length)};
        int[] processed = {0};

        return mapChunks(input, blockSize, (chunk, chunkIndex) -> {
            // 현재 카운터 블록을 암호화해 이번 청크용 keystream을 생성합니다.
            byte[] stream = cipher.encryptBlock(counter[0]);
            byte[] streamChunk = Bytes.slice(stream, 0, chunk.length);
            byte[] outChunk = Bytes.xor(chunk, streamChunk);

            // keystream 사용 후 카운터를 반드시 증가시킵니다.
            boolean wrapped = Bytes.incrementBigEndian(counter[0]);
            processed[0] += chunk.length;
            // 카운터 공간이 모두 소진됐는데 입력이 남아 있으면 안전하지 않으므로 중단합니다.
            if (wrapped && processed[0] < input.length) {
                throw new IllegalStateException("CTR counter wrapped; nonce/counter space exhausted");
            }
            return outChunk;
        });
    }
}
