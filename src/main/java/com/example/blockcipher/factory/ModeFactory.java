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

/**
 * 모드 구현체 생성 팩토리입니다.
 *
 * <p>ECB/CBC에는 PKCS#7 패딩을 주입하고,
 * CFB/OFB/CTR는 스트림 유사 동작이라 별도 패딩 없이 생성합니다.</p>
 */
public final class ModeFactory {
    private ModeFactory() {
    }

    /**
     * 요청된 모드 타입에 맞는 구현체를 생성합니다.
     *
     * @param type 모드 타입
     * @param cipher 단일 블록 암호 원시함수
     * @return 모드 구현체
     */
    public static ModeOfOperation create(ModeType type, BlockCipher cipher) {
        PaddingScheme pkcs7 = new Pkcs7Padding();
        return switch (type) {
            case ECB -> new ECBMode(cipher, pkcs7);
            case CBC -> new CBCMode(cipher, pkcs7);
            case CFB -> new CFBMode(cipher);
            case OFB -> new OFBMode(cipher);
            case CTR -> new CTRMode(cipher);
        };
    }
}
