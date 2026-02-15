package com.example.blockcipher.padding;

/**
 * 블록 패딩 스킴 인터페이스입니다.
 *
 * <p>ECB/CBC처럼 입력 길이가 블록 배수여야 하는 모드에서 사용합니다.</p>
 */
public interface PaddingScheme {
    /**
     * 입력 데이터에 패딩을 추가해 블록 배수 길이로 만듭니다.
     *
     * @param input 원본 데이터
     * @param blockSize 블록 크기(바이트)
     * @return 패딩이 적용된 데이터
     */
    byte[] pad(byte[] input, int blockSize);

    /**
     * 패딩을 제거해 원본 데이터로 복원합니다.
     *
     * @param input 패딩 포함 데이터
     * @param blockSize 블록 크기(바이트)
     * @return 패딩 제거 데이터
     */
    byte[] unpad(byte[] input, int blockSize);
}
