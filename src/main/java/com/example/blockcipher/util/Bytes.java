package com.example.blockcipher.util;

import java.util.Arrays;
import java.util.stream.IntStream;

/**
 * 바이트 배열 연산 유틸리티입니다.
 */
public final class Bytes {
    private Bytes() {
    }

    /**
     * 두 배열을 같은 인덱스끼리 XOR합니다.
     *
     * <p>반복은 IntStream으로 수행합니다.</p>
     */
    public static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("xor requires arrays of equal length");
        }
        byte[] out = new byte[a.length];
        IntStream.range(0, a.length)
            .sequential()
            .forEach(i -> out[i] = (byte) (a[i] ^ b[i]));
        return out;
    }

    /**
     * 입력 배열의 일부 구간을 복사해 새 배열로 반환합니다.
     */
    public static byte[] slice(byte[] input, int offset, int length) {
        return Arrays.copyOfRange(input, offset, offset + length);
    }

    /**
     * 빅엔디언 counter 배열을 1 증가시킵니다.
     *
     * <p>이 로직은 carry 전파가 핵심이므로 Stream보다 일반 반복이 명확합니다.</p>
     *
     * @return 전체가 0으로 돌아왔으면 true(overflow wrap), 아니면 false
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
     * 두 배열을 앞뒤로 이어붙입니다.
     */
    public static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
