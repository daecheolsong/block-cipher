package com.example.blockcipher.padding;

import java.util.Arrays;

/**
 * PKCS#7 패딩 구현입니다.
 *
 * <p>규칙:
 * <pre>
 * padLen = blockSize - (len mod blockSize)
 * (len mod blockSize == 0 이면 padLen = blockSize)
 * 결과 = 입력 || [padLen 값을 padLen번 반복]
 * </pre>
 *
 * 예: blockSize=16, 마지막 바이트가 {@code 0x04}이면 끝의 4바이트가 모두 {@code 0x04}여야 합니다.</p>
 */
public final class Pkcs7Padding implements PaddingScheme {
    /**
     * PKCS#7 패딩을 추가합니다.
     */
    @Override
    public byte[] pad(byte[] input, int blockSize) {
        if (input == null) {
            throw new IllegalArgumentException("input must not be null");
        }
        if (blockSize <= 0 || blockSize > 255) {
            throw new IllegalArgumentException("blockSize must be between 1 and 255");
        }
        int padLength = blockSize - (input.length % blockSize);
        if (padLength == 0) {
            padLength = blockSize;
        }
        byte[] out = Arrays.copyOf(input, input.length + padLength);
        Arrays.fill(out, input.length, out.length, (byte) padLength);
        return out;
    }

    /**
     * PKCS#7 패딩을 검증하고 제거합니다.
     */
    @Override
    public byte[] unpad(byte[] input, int blockSize) {
        if (input == null) {
            throw new IllegalArgumentException("input must not be null");
        }
        if (input.length == 0 || input.length % blockSize != 0) {
            throw new IllegalArgumentException("invalid padded input length");
        }
        int padLength = input[input.length - 1] & 0xFF;
        if (padLength == 0 || padLength > blockSize || padLength > input.length) {
            throw new IllegalArgumentException("invalid PKCS#7 padding length");
        }
        for (int i = input.length - padLength; i < input.length; i++) {
            if ((input[i] & 0xFF) != padLength) {
                throw new IllegalArgumentException("invalid PKCS#7 padding bytes");
            }
        }
        return Arrays.copyOf(input, input.length - padLength);
    }
}
