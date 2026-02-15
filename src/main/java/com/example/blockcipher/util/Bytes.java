package com.example.blockcipher.util;

import java.util.Arrays;

/**
 * 바이트 배열 연산 유틸리티입니다.
 */
public final class Bytes {
    private Bytes() {
    }

    /**
     * 동일 길이 배열의 XOR 결과를 반환합니다.
     */
    public static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("xor requires arrays of equal length");
        }
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    /**
     * 배열의 부분 구간을 잘라 새 배열로 반환합니다.
     */
    public static byte[] slice(byte[] input, int offset, int length) {
        return Arrays.copyOfRange(input, offset, offset + length);
    }

    /**
     * 빅엔디언 카운터를 1 증가시킵니다.
     *
     * @return 전체 바이트가 0으로 되돌아 wrap되었으면 true
     */
    public static boolean incrementBigEndian(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            counter[i]++;
            if (counter[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * 두 배열을 이어붙입니다.
     */
    public static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
