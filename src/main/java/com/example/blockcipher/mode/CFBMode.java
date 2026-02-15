package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;
import com.example.blockcipher.util.Bytes;
import java.util.Arrays;

/**
 * CFB 모드 구현입니다.
 *
 * <p>본 구현은 블록 단위 CFB(세그먼트 크기 s = 블록 크기 b) 기준입니다.</p>
 * <p>{@code O_i = E_k(C_{i-1})}, {@code C_0 = IV}</p>
 * <p>{@code C_i = P_i xor O_i}</p>
 * <p>{@code P_i = C_i xor O_i}</p>
 *
 * <p>CFB의 핵심은 복호화에서도 {@code decryptBlock}이 아니라
 * {@code encryptBlock}으로 keystream을 만든다는 점입니다.</p>
 */
public final class CFBMode extends AbstractMode {
    /**
     * @param cipher 단일 블록 암호 함수
     */
    public CFBMode(BlockCipher cipher) {
        super(cipher);
    }

    @Override
    public ModeType type() {
        return ModeType.CFB;
    }

    /**
     * CFB 암호화를 수행합니다.
     *
     * <p>처리 순서</p>
     * <p>1. 현재 feedback(처음은 IV)을 암호화해 keystream 생성</p>
     * <p>2. 평문 청크와 keystream 청크를 XOR해 암호문 청크 생성</p>
     * <p>3. 블록 단위 처리에서는 방금 만든 암호문을 다음 feedback으로 사용</p>
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        int blockSize = cipher.blockSize();
        byte[][] feedback = {Arrays.copyOf(ivOrNonce, ivOrNonce.length)};

        return mapChunks(plaintext, blockSize, (chunk, chunkIndex) -> {
            // feedback(처음은 IV)를 암호화해 이번 청크용 keystream을 만듭니다.
            byte[] stream = cipher.encryptBlock(feedback[0]);
            byte[] streamChunk = Bytes.slice(stream, 0, chunk.length);
            byte[] cipherChunk = Bytes.xor(chunk, streamChunk);

            // 블록 단위 처리라면 방금 만든 암호문이 다음 feedback이 됩니다.
            if (chunk.length == blockSize) {
                feedback[0] = cipherChunk;
            }
            return cipherChunk;
        });
    }

    /**
     * CFB 복호화를 수행합니다.
     *
     * <p>처리 순서는 암호화와 거의 같고, XOR 대상만 암호문 청크로 바뀝니다.</p>
     * <p>1. 현재 feedback을 암호화해 keystream 생성</p>
     * <p>2. 암호문 청크와 keystream 청크 XOR -> 평문 청크</p>
     * <p>3. 블록 단위 처리에서는 "입력 암호문 청크"를 다음 feedback으로 사용</p>
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        int blockSize = cipher.blockSize();
        byte[][] feedback = {Arrays.copyOf(ivOrNonce, ivOrNonce.length)};

        return mapChunks(ciphertext, blockSize, (chunk, chunkIndex) -> {
            // 복호화에서도 동일하게 feedback을 암호화해 keystream을 생성합니다.
            byte[] stream = cipher.encryptBlock(feedback[0]);
            byte[] streamChunk = Bytes.slice(stream, 0, chunk.length);
            byte[] plainChunk = Bytes.xor(chunk, streamChunk);

            // 다음 feedback은 "출력 평문"이 아니라 "입력 암호문"입니다.
            if (chunk.length == blockSize) {
                feedback[0] = chunk;
            }
            return plainChunk;
        });
    }
}
