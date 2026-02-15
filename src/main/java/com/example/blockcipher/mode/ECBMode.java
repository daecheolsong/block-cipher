package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;
import com.example.blockcipher.padding.PaddingScheme;

/**
 * ECB 모드 구현입니다.
 *
 * <p>수식은 다음과 같습니다.</p>
 * <p>{@code C_i = E_k(P_i)}</p>
 * <p>{@code P_i = D_k(C_i)}</p>
 *
 * <p>각 블록이 독립적으로 처리되기 때문에,
 * 같은 평문 블록은 항상 같은 암호문 블록으로 변환됩니다.
 * 본 구현은 평문 입력에 PKCS#7 패딩을 적용합니다.</p>
 */
public final class ECBMode extends AbstractMode {
    /** ECB에서 사용할 패딩 정책(PKCS#7 등). */
    private final PaddingScheme padding;

    /**
     * @param cipher 단일 블록 암호 함수
     * @param padding 평문 길이 정렬용 패딩 정책
     */
    public ECBMode(BlockCipher cipher, PaddingScheme padding) {
        super(cipher);
        this.padding = padding;
    }

    @Override
    public ModeType type() {
        return ModeType.ECB;
    }

    /**
     * ECB는 IV/nonce를 사용하지 않습니다.
     */
    @Override
    public int ivLength() {
        return 0;
    }

    /**
     * 평문을 ECB 규칙으로 암호화합니다.
     *
     * <p>처리 순서</p>
     * <p>1. IV 전달이 없는지 확인</p>
     * <p>2. 패딩 적용</p>
     * <p>3. 각 블록을 독립적으로 {@code E_k} 처리</p>
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] ivOrNonce) {
        if (ivOrNonce != null && ivOrNonce.length > 0) {
            throw new IllegalArgumentException("ECB does not use IV/nonce");
        }
        byte[] padded = padding.pad(plaintext, cipher.blockSize());
        return mapFullBlocks(padded, (block, blockIndex) -> cipher.encryptBlock(block));
    }

    /**
     * 암호문을 ECB 규칙으로 복호화합니다.
     *
     * <p>처리 순서</p>
     * <p>1. IV 전달이 없는지 확인</p>
     * <p>2. 각 블록을 독립적으로 {@code D_k} 처리</p>
     * <p>3. 패딩 제거</p>
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] ivOrNonce) {
        if (ivOrNonce != null && ivOrNonce.length > 0) {
            throw new IllegalArgumentException("ECB does not use IV/nonce");
        }
        byte[] paddedPlain = mapFullBlocks(ciphertext, (block, blockIndex) -> cipher.decryptBlock(block));
        return padding.unpad(paddedPlain, cipher.blockSize());
    }
}
