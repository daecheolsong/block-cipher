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
 * 간단한 실행 데모입니다.
 *
 * <p>랜덤 AES 키를 만든 뒤 CTR 모드로 암호화/복호화를 수행하고,
 * 결과를 hex/문자열로 출력합니다.</p>
 */
public final class DemoApplication {
    private DemoApplication() {
    }

    /**
     * 데모 엔트리포인트.
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
