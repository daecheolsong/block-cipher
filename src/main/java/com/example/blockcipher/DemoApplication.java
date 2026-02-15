package com.example.blockcipher;

import com.example.blockcipher.core.AesBlockCipher;
import com.example.blockcipher.factory.ModeFactory;
import com.example.blockcipher.mode.ModeOfOperation;
import com.example.blockcipher.mode.ModeType;
import com.example.blockcipher.service.ModeCipherService;
import com.example.blockcipher.util.Hex;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * 프로젝트 동작을 빠르게 확인하기 위한 콘솔 데모 프로그램입니다.
 */
public final class DemoApplication {
    private DemoApplication() {
    }

    /**
     * 실행 순서
     *
     * <p>1. 랜덤 AES 키 생성</p>
     * <p>2. CTR 모드 인스턴스 생성</p>
     * <p>3. 평문 암호화</p>
     * <p>4. 다시 복호화</p>
     * <p>5. 결과 출력</p>
     */
    public static void main(String[] args) {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);

        ModeOfOperation mode = ModeFactory.create(ModeType.CTR, new AesBlockCipher(key));
        ModeCipherService service = new ModeCipherService(mode);

        byte[] plaintext = "Block cipher mode demo".getBytes(StandardCharsets.UTF_8);
        byte[] packed = service.encryptWithHeader(plaintext);
        byte[] restored = service.decryptWithHeader(packed);

        System.out.println("mode      : " + mode.type());
        System.out.println("encrypted : " + Hex.encode(packed));
        System.out.println("decrypted : " + new String(restored, StandardCharsets.UTF_8));
    }
}
