package com.example.blockcipher.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.example.blockcipher.core.AesBlockCipher;
import com.example.blockcipher.factory.ModeFactory;
import com.example.blockcipher.service.ModeCipherService;
import java.util.Arrays;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * 모든 모드에서 암호화 후 복호화했을 때 원문이 정확히 복원되는지 검증합니다.
 */
class ModeRoundTripTest {
    /**
     * 모드 종류와 입력 길이를 조합해 반복 테스트합니다.
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
     * 재현 가능한 테스트를 위해 고정 시드 난수를 사용합니다.
     */
    private static byte[] randomBytes(int length, int seed) {
        byte[] out = new byte[length];
        new Random(seed).nextBytes(out);
        return out;
    }

    /**
     * (모드 x 길이) 테스트 조합을 생성합니다.
     */
    private static Stream<Arguments> cases() {
        int[] lengths = {0, 1, 15, 16, 31, 32, 100};
        return Stream.of(ModeType.values())
            .flatMap(mode -> Arrays.stream(lengths).mapToObj(length -> Arguments.of(mode, length)));
    }
}
