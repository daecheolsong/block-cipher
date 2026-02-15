package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;

/**
 * 모드 구현에서 공통으로 사용하는 검증 로직을 모아둔 추상 클래스입니다.
 */
abstract class AbstractMode implements ModeOfOperation {
    /** 단일 블록 암호 원시함수 {@code E_k}/{@code D_k}. */
    protected final BlockCipher cipher;

    AbstractMode(BlockCipher cipher) {
        this.cipher = cipher;
    }

    @Override
    public int ivLength() {
        return cipher.blockSize();
    }

    /**
     * IV/nonce 길이가 블록 크기와 정확히 같은지 검사합니다.
     */
    protected void requireIv(byte[] ivOrNonce) {
        if (ivOrNonce == null || ivOrNonce.length != ivLength()) {
            throw new IllegalArgumentException("iv/nonce must be exactly " + ivLength() + " bytes");
        }
    }

    /**
     * 입력 길이가 블록 크기의 배수인지 검사합니다.
     * (ECB/CBC의 암호문 복호화 등에서 필요)
     */
    protected void requireMultipleBlockLength(byte[] input) {
        if (input.length % cipher.blockSize() != 0) {
            throw new IllegalArgumentException(
                "input length must be a multiple of block size (" + cipher.blockSize() + " bytes)"
            );
        }
    }
}
