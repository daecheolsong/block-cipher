package com.example.blockcipher.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.example.blockcipher.core.AesBlockCipher;
import com.example.blockcipher.factory.ModeFactory;
import com.example.blockcipher.service.ModeCipherService;
import java.util.Arrays;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * 모든 모드에 대해 암호화-복호화 round-trip이 원문을 보존하는지 검증합니다.
 */
class ModeRoundTripTest {
    /**
     * 모드별/길이별 케이스를 순회하며 복원 결과를 검사합니다.
     */
    @ParameterizedTest
    @MethodSource("cases")
    void roundTrip(ModeType modeType, int length) {
        byte[] key = randomBytes(16, 7);
        byte[] plaintext = randomBytes(length, 11 + length);

        ModeOfOperation mode = ModeFactory.create(modeType, new AesBlockCipher(key));
        ModeCipherService service = new ModeCipherService(mode);

        byte[] packed = service.encryptWithHeader(plaintext);
        byte[] restored = service.decryptWithHeader(packed);

        assertArrayEquals(plaintext, restored);
    }

    /**
     * 재현 가능한 테스트를 위해 고정 seed 난수 바이트를 생성합니다.
     */
    private static byte[] randomBytes(int length, int seed) {
        byte[] out = new byte[length];
        new Random(seed).nextBytes(out);
        return out;
    }

    /**
     * (모드 x 길이) 조합 테스트 케이스를 생성합니다.
     */
    private static Stream<Arguments> cases() {
        int[] lengths = {0, 1, 15, 16, 31, 32, 100};
        return Stream.of(ModeType.values())
            .flatMap(mode -> Arrays.stream(lengths).mapToObj(length -> Arguments.of(mode, length)));
    }
}
