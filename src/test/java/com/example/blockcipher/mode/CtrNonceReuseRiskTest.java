package com.example.blockcipher.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.example.blockcipher.core.AesBlockCipher;
import com.example.blockcipher.util.Bytes;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * CTR에서 nonce/counter 블록을 재사용하면 발생하는 XOR 누출을 재현하는 테스트입니다.
 */
class CtrNonceReuseRiskTest {
    /**
     * 같은 키/nonce를 재사용하면
     * {@code C1 xor C2 = P1 xor P2} 관계가 성립함을 확인합니다.
     */
    @Test
    void reusingSameNonceLeaksXorRelation() {
        byte[] key = new byte[16];
        byte[] nonceAndCounter = new byte[16];

        byte[] p1 = "transfer=1000;to=alice".getBytes(StandardCharsets.UTF_8);
        byte[] p2 = "transfer=9000;to=bob!!".getBytes(StandardCharsets.UTF_8);

        CTRMode ctr = new CTRMode(new AesBlockCipher(key));
        byte[] c1 = ctr.encrypt(p1, nonceAndCounter);
        byte[] c2 = ctr.encrypt(p2, nonceAndCounter);

        byte[] xorCipher = Bytes.xor(c1, c2);
        byte[] xorPlain = Bytes.xor(p1, p2);
        assertArrayEquals(xorPlain, xorCipher);
    }
}
