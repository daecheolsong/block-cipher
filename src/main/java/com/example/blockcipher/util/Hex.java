package com.example.blockcipher.util;

/**
 * Hex 인코딩/디코딩 유틸리티입니다.
 */
public final class Hex {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    /**
     * 바이트 배열을 소문자 hex 문자열로 변환합니다.
     */
    public static String encode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            int v = b & 0xFF;
            sb.append(HEX[v >>> 4]);
            sb.append(HEX[v & 0x0F]);
        }
        return sb.toString();
    }

    /**
     * hex 문자열을 바이트 배열로 변환합니다.
     * 공백 문자는 무시합니다.
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
        for (int i = 0; i < normalized.length(); i += 2) {
            int high = toNibble(normalized.charAt(i));
            int low = toNibble(normalized.charAt(i + 1));
            out[i / 2] = (byte) ((high << 4) | low);
        }
        return out;
    }

    /**
     * hex 문자 1개를 0~15 정수값으로 변환합니다.
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
