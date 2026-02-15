package com.example.blockcipher.padding;

import java.util.Arrays;
import java.util.stream.IntStream;

/**
 * PKCS#7 패딩 구현입니다.
 *
 * <p>패딩 규칙</p>
 * <p>{@code padLen = blockSize - (len mod blockSize)}</p>
 * <p>{@code len mod blockSize == 0}인 경우 {@code padLen = blockSize}</p>
 * <p>마지막에 {@code padLen} 값을 {@code padLen}번 반복해 붙입니다.</p>
 *
 * <p>예: blockSize=16, padLen=4이면 끝 4바이트는 모두 0x04입니다.</p>
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
     * PKCS#7 패딩을 검증한 뒤 제거합니다.
     *
     * <p>검증 항목</p>
     * <p>1. 전체 길이가 블록 배수인지</p>
     * <p>2. 마지막 바이트가 유효한 padLength인지</p>
     * <p>3. 끝 padLength 바이트가 모두 같은 값인지</p>
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
        boolean invalidPaddingByte = IntStream.range(input.length - padLength, input.length)
            .anyMatch(i -> (input[i] & 0xFF) != padLength);
        if (invalidPaddingByte) {
            throw new IllegalArgumentException("invalid PKCS#7 padding bytes");
        }
        return Arrays.copyOf(input, input.length - padLength);
    }
}
