package com.example.blockcipher.core;

/**
 * JCA/암호 연산 중 발생한 예외를 런타임 예외로 래핑하기 위한 타입입니다.
 */
public final class CryptoException extends RuntimeException {
    /**
     * @param message 오류 요약
     * @param cause 원인 예외
     */
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
