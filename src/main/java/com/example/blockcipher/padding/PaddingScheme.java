package com.example.blockcipher.padding;

/**
 * 블록 패딩 정책을 정의하는 인터페이스입니다.
 *
 * <p>블록 암호는 입력 길이가 블록 크기의 배수여야 하므로,
 * ECB/CBC 같은 모드에서 이 인터페이스를 통해 패딩을 붙이고 제거합니다.</p>
 */
public interface PaddingScheme {
    /**
     * 입력 데이터를 블록 배수 길이로 맞추기 위해 패딩을 추가합니다.
     *
     * @param input 원본 바이트 배열
     * @param blockSize 블록 크기(바이트)
     * @return 패딩이 추가된 배열
     */
    byte[] pad(byte[] input, int blockSize);

    /**
     * 패딩을 검증하고 제거합니다.
     *
     * @param input 패딩이 포함된 배열
     * @param blockSize 블록 크기(바이트)
     * @return 패딩 제거 후 배열
     */
    byte[] unpad(byte[] input, int blockSize);
}
