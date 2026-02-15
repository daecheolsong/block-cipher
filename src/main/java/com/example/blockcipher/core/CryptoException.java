package com.example.blockcipher.core;

/**
 * 암호 라이브러리(JCA) 호출 중 발생한 예외를 감싸는 런타임 예외입니다.
 *
 * <p>체크 예외를 상위 계층으로 전파하지 않고, 프로젝트 내부에서 암호 오류를
 * 하나의 유형으로 다루기 위해 사용합니다.</p>
 */
public final class CryptoException extends RuntimeException {
    /**
     * @param message 오류 요약 메시지
     * @param cause 원본 예외
     */
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
