package com.example.blockcipher.mode;

import com.example.blockcipher.core.BlockCipher;
import com.example.blockcipher.util.Bytes;
import java.util.stream.IntStream;

/**
 * 모드 구현에서 공통으로 쓰는 검증/순회 유틸을 모아둔 추상 클래스입니다.
 *
 * <p>요청하신 대로 반복 구간은 Stream API(IntStream)로 구성했고,
 * 상태가 필요한 모드(CBC/CFB/OFB/CTR)를 위해 반드시 순차 실행으로 동작합니다.</p>
 */
abstract class AbstractMode implements ModeOfOperation {
    /** 단일 블록 암호 원시 연산 객체(AES 등). */
    protected final BlockCipher cipher;

    /**
     * 블록 단위 변환 함수 타입입니다.
     *
     * @param block 현재 블록 데이터
     * @param blockIndex 현재 블록 인덱스
     * @return 변환된 블록(반드시 원본 블록과 같은 길이)
     */
    @FunctionalInterface
    protected interface FullBlockTransformer {
        byte[] apply(byte[] block, int blockIndex);
    }

    /**
     * 청크 단위 변환 함수 타입입니다.
     *
     * <p>마지막 청크는 블록보다 짧을 수 있으므로, 청크 길이를 그대로 반환해야 합니다.</p>
     */
    @FunctionalInterface
    protected interface ChunkTransformer {
        byte[] apply(byte[] chunk, int chunkIndex);
    }

    AbstractMode(BlockCipher cipher) {
        this.cipher = cipher;
    }

    @Override
    public int ivLength() {
        return cipher.blockSize();
    }

    /**
     * IV/nonce 길이 검증.
     */
    protected void requireIv(byte[] ivOrNonce) {
        if (ivOrNonce == null || ivOrNonce.length != ivLength()) {
            throw new IllegalArgumentException("iv/nonce must be exactly " + ivLength() + " bytes");
        }
    }

    /**
     * 입력 길이가 블록 크기의 배수인지 검증.
     */
    protected void requireMultipleBlockLength(byte[] input) {
        if (input.length % cipher.blockSize() != 0) {
            throw new IllegalArgumentException(
                "input length must be a multiple of block size (" + cipher.blockSize() + " bytes)"
            );
        }
    }

    /**
     * 블록 단위 입력을 Stream API로 순회해 변환합니다.
     *
     * <p>IntStream은 기본이 순차지만, 실수로 병렬 변경되는 것을 막기 위해
     * {@code sequential()}을 명시했습니다.</p>
     */
    protected byte[] mapFullBlocks(byte[] input, FullBlockTransformer transformer) {
        requireMultipleBlockLength(input);
        int blockSize = cipher.blockSize();
        int blockCount = input.length / blockSize;
        byte[] out = new byte[input.length];

        IntStream.range(0, blockCount)
            .sequential()
            .forEach(blockIndex -> {
                int offset = blockIndex * blockSize;
                byte[] block = Bytes.slice(input, offset, blockSize);
                byte[] transformed = transformer.apply(block, blockIndex);
                requireLength(transformed, blockSize, "full-block transform result");
                System.arraycopy(transformed, 0, out, offset, blockSize);
            });

        return out;
    }

    /**
     * 가변 길이 입력을 청크 단위로 Stream API 순회해 변환합니다.
     */
    protected byte[] mapChunks(byte[] input, int chunkSize, ChunkTransformer transformer) {
        if (chunkSize <= 0) {
            throw new IllegalArgumentException("chunkSize must be positive");
        }
        int chunkCount = (input.length + chunkSize - 1) / chunkSize;
        byte[] out = new byte[input.length];

        IntStream.range(0, chunkCount)
            .sequential()
            .forEach(chunkIndex -> {
                int offset = chunkIndex * chunkSize;
                int length = Math.min(chunkSize, input.length - offset);
                byte[] chunk = Bytes.slice(input, offset, length);
                byte[] transformed = transformer.apply(chunk, chunkIndex);
                requireLength(transformed, length, "chunk transform result");
                System.arraycopy(transformed, 0, out, offset, length);
            });

        return out;
    }

    /**
     * 내부 길이 검증 유틸.
     */
    private static void requireLength(byte[] bytes, int expected, String label) {
        if (bytes == null || bytes.length != expected) {
            throw new IllegalStateException(label + " length must be " + expected + " bytes");
        }
    }
}
