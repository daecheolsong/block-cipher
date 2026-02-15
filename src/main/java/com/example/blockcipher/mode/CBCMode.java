package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;
import com.example.blockcipher.padding.PaddingScheme;
import com.example.blockcipher.util.Bytes;
import java.util.Arrays;

/**
 * CBC 모드 구현입니다.
 *
 * <p>암호화 수식</p>
 * <p>{@code C_1 = E_k(P_1 xor IV)}</p>
 * <p>{@code C_i = E_k(P_i xor C_{i-1})}, i >= 2</p>
 *
 * <p>복호화 수식</p>
 * <p>{@code P_1 = D_k(C_1) xor IV}</p>
 * <p>{@code P_i = D_k(C_i) xor C_{i-1}}, i >= 2</p>
 */
public final class CBCMode extends AbstractMode {
    /** CBC에서 사용할 패딩 정책(PKCS#7 등). */
    private final PaddingScheme padding;

    /**
     * @param cipher 단일 블록 암호 함수
     * @param padding 평문 길이 정렬용 패딩 정책
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
     * CBC 암호화를 수행합니다.
     *
     * <p>처리 순서</p>
     * <p>1. IV 길이 검증</p>
     * <p>2. 평문 패딩</p>
     * <p>3. 현재 평문 블록과 이전 암호문 블록(첫 블록은 IV)을 XOR</p>
     * <p>4. XOR 결과를 블록 암호화</p>
     * <p>5. 방금 생성한 암호문 블록을 다음 체인 값으로 사용</p>
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        byte[] padded = padding.pad(plaintext, cipher.blockSize());
        byte[][] previous = {Arrays.copyOf(ivOrNonce, ivOrNonce.length)};

        return mapFullBlocks(padded, (block, blockIndex) -> {
            // 현재 평문 블록과 이전 암호문 블록(첫 블록은 IV)을 결합합니다.
            byte[] chained = Bytes.xor(block, previous[0]);
            // 결합 결과를 블록 암호화하면 현재 암호문 블록이 됩니다.
            byte[] encrypted = cipher.encryptBlock(chained);
            // 다음 블록 처리를 위해 체인 값을 현재 암호문으로 갱신합니다.
            previous[0] = encrypted;
            return encrypted;
        });
    }

    /**
     * CBC 복호화를 수행합니다.
     *
     * <p>처리 순서</p>
     * <p>1. IV 길이 검증</p>
     * <p>2. 현재 암호문 블록을 블록 복호화</p>
     * <p>3. 복호화 결과와 이전 암호문 블록(첫 블록은 IV)을 XOR</p>
     * <p>4. 현재 암호문 블록을 다음 체인 값으로 갱신</p>
     * <p>5. 마지막에 패딩 제거</p>
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce) {
        requireIv(ivOrNonce);
        byte[][] previous = {Arrays.copyOf(ivOrNonce, ivOrNonce.length)};

        byte[] paddedPlain = mapFullBlocks(ciphertext, (block, blockIndex) -> {
            // 현재 암호문 블록을 먼저 블록 복호화합니다.
            byte[] decrypted = cipher.decryptBlock(block);
            // 복호화 결과와 이전 암호문 블록(첫 블록은 IV)을 XOR해 평문을 얻습니다.
            byte[] plainBlock = Bytes.xor(decrypted, previous[0]);
            // 다음 반복에서 사용할 이전 암호문을 현재 암호문으로 교체합니다.
            previous[0] = block;
            return plainBlock;
        });
        return padding.unpad(paddedPlain, cipher.blockSize());
    }
}
