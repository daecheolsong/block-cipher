# Java 클래스 설계

## 설계 목표

- 모드 로직과 블록 암호 프리미티브를 분리
- 수학식과 코드 흐름을 1:1로 추적 가능하게 유지
- 모드 추가 시 기존 코드 변경 최소화 (factory + interface 기반)

## 핵심 타입

### `BlockCipher`

- 역할: 단일 블록 암/복호화 프리미티브
- 구현: `AesBlockCipher` (`AES/ECB/NoPadding`을 내부 block primitive로만 사용)
- 이유: 모드 구현에서 `E_k`, `D_k`를 직접 조합하기 쉬움

### `ModeOfOperation`

- 역할: 모드 통합 API
- 메서드:
  - `type()`
  - `ivLength()`
  - `encrypt(plaintext, ivOrNonce)`
  - `decrypt(ciphertext, ivOrNonce)`

### `AbstractMode`

- 역할: 공통 검증 로직
  - IV/nonce 길이 검사
  - 블록 배수 길이 검사(필요 모드에서 사용)

### 모드 구현체

- `ECBMode`: 독립 블록 암복호 + 패딩
- `CBCMode`: 체이닝 XOR + 패딩
- `CFBMode`: feedback 기반 stream-like 처리 (full-block)
- `OFBMode`: output feedback keystream
- `CTRMode`: counter keystream (`counter++`, wrap 검사)

### `PaddingScheme`

- 역할: 패딩 정책 추상화
- 구현: `Pkcs7Padding`
- 적용 모드: ECB, CBC

### `ModeFactory`

- 역할: `ModeType` -> 구현체 생성
- 확장: 신규 모드 추가 시 switch에 타입 1건 추가

### `ModeCipherService`

- 역할: 실사용 편의 API
  - 암호화 시 IV 생성 후 `[IV|Ciphertext]` 패킹
  - 복호화 시 헤더 분리 후 모드 호출

