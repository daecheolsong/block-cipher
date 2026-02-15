package com.example.blockcipher.util;

import java.util.stream.IntStream;

/**
 * Hex 문자열 인코딩/디코딩 유틸리티입니다.
 */
public final class Hex {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    /**
     * 바이트 배열을 16진수 문자열로 변환합니다.
     *
     * <p>반복 처리는 IntStream으로 수행합니다.</p>
     */
    public static String encode(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        IntStream.range(0, bytes.length)
            .sequential()
            .forEach(i -> {
                int v = bytes[i] & 0xFF;
                out[i * 2] = HEX[v >>> 4];
                out[(i * 2) + 1] = HEX[v & 0x0F];
            });
        return new String(out);
    }

    /**
     * 16진수 문자열을 바이트 배열로 변환합니다.
     *
     * <p>문자열의 공백은 제거한 뒤 처리합니다.</p>
     */
    public static byte[] decode(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex must not be null");
        }
        String normalized = hex.replaceAll("\\s+", "");
        if (normalized.isEmpty()) {
            return new byte[0];
        }
        if ((normalized.length() & 1) != 0) {
            throw new IllegalArgumentException("hex string length must be even");
        }

        byte[] out = new byte[normalized.length() / 2];
        IntStream.range(0, out.length)
            .sequential()
            .forEach(i -> {
                int index = i * 2;
                int high = toNibble(normalized.charAt(index));
                int low = toNibble(normalized.charAt(index + 1));
                out[i] = (byte) ((high << 4) | low);
            });
        return out;
    }

    /**
     * hex 문자 한 개를 0~15 값으로 변환합니다.
     */
    private static int toNibble(char c) {
        if ('0' <= c && c <= '9') {
            return c - '0';
        }
        if ('a' <= c && c <= 'f') {
            return 10 + (c - 'a');
        }
        if ('A' <= c && c <= 'F') {
            return 10 + (c - 'A');
        }
        throw new IllegalArgumentException("invalid hex character: " + c);
    }
}
