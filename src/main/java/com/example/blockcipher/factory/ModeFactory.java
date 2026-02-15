package com.example.blockcipher.factory;

import com.example.blockcipher.core.BlockCipher;
import com.example.blockcipher.mode.CBCMode;
import com.example.blockcipher.mode.CFBMode;
import com.example.blockcipher.mode.CTRMode;
import com.example.blockcipher.mode.ECBMode;
import com.example.blockcipher.mode.ModeOfOperation;
import com.example.blockcipher.mode.ModeType;
import com.example.blockcipher.mode.OFBMode;
import com.example.blockcipher.padding.PaddingScheme;
import com.example.blockcipher.padding.Pkcs7Padding;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * 모드 구현체를 생성하는 팩토리입니다.
 *
 * <p>모드 타입별 생성 함수를 표(Map)로 보관해 두고,
 * 호출 시 해당 생성 함수를 꺼내 실행하는 방식으로 동작합니다.</p>
 */
public final class ModeFactory {
    /** ECB/CBC에서 공통으로 사용할 PKCS#7 패딩 인스턴스. */
    private static final PaddingScheme PKCS7 = new Pkcs7Padding();

    /** 모드 타입 -> 생성 함수 매핑 표. */
    private static final Map<ModeType, Function<BlockCipher, ModeOfOperation>> BUILDERS = createBuilders();

    private ModeFactory() {
    }

    /**
     * 지정된 모드 타입에 맞는 구현체를 생성합니다.
     *
     * @param type 생성할 모드 타입
     * @param cipher 사용할 블록 암호 구현체(AES 등)
     * @return 모드 구현체
     */
    public static ModeOfOperation create(ModeType type, BlockCipher cipher) {
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(cipher, "cipher must not be null");

        Function<BlockCipher, ModeOfOperation> builder = BUILDERS.get(type);
        if (builder == null) {
            throw new IllegalArgumentException("unsupported mode type: " + type);
        }
        return builder.apply(cipher);
    }

    /**
     * 모드 타입별 생성 함수를 등록합니다.
     *
     * <p>ECB/CBC는 패딩이 필요하므로 PKCS7을 주입하고,
     * CFB/OFB/CTR는 패딩 없이 생성합니다.</p>
     */
    private static Map<ModeType, Function<BlockCipher, ModeOfOperation>> createBuilders() {
        EnumMap<ModeType, Function<BlockCipher, ModeOfOperation>> map = new EnumMap<>(ModeType.class);
        map.put(ModeType.ECB, cipher -> new ECBMode(cipher, PKCS7));
        map.put(ModeType.CBC, cipher -> new CBCMode(cipher, PKCS7));
        map.put(ModeType.CFB, CFBMode::new);
        map.put(ModeType.OFB, OFBMode::new);
        map.put(ModeType.CTR, CTRMode::new);
        return Map.copyOf(map);
    }
}
