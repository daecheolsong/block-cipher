# Block Cipher Modes (Java)

Educational Java implementation of block cipher modes and a Swing visualizer for step-by-step execution tracing.

## Supported Modes

- `ECB`
- `CBC`
- `CFB` (full-block variant)
- `OFB`
- `CTR`

## Project Layout

```text
src/main/java/com/example/blockcipher
|- core
|  |- BlockCipher.java
|  |- AesBlockCipher.java
|  `- CryptoException.java
|- mode
|  |- ModeOfOperation.java
|  |- ModeType.java
|  |- AbstractMode.java
|  |- ECBMode.java
|  |- CBCMode.java
|  |- CFBMode.java
|  |- OFBMode.java
|  `- CTRMode.java
|- padding
|- factory
|- service
|- util
`- DemoApplication.java
```

## Swing Visualizer

- Main class: `com.example.blockcipher.visualizer.ui.VisualizerApplication`
- Features:
  - Mode/direction selection
  - Key/IV input validation
  - Full trace table (`XOR`, `E_k`, `D_k`, feedback, counter)
  - Color-coded step table by operation type
  - Step inspector (hex + UTF-8 + note context)
  - Mode-specific flow diagrams (ECB/CBC/CFB/OFB/CTR)
  - Step progress timeline
  - Byte-strip visualization for left/right/result values
  - Playback controls (`Prev/Next/Play/Stop`, speed slider)

## Tests

- `src/test/java/com/example/blockcipher/mode/ModeRoundTripTest.java`
- `src/test/java/com/example/blockcipher/mode/EcbPatternLeakageTest.java`
- `src/test/java/com/example/blockcipher/mode/CtrNonceReuseRiskTest.java`

## Run

If Maven is available:

```bash
mvn test
```

## Documents

- Core class design: `docs/CLASS_DESIGN.md`
- NIST formula references: `docs/FORMULA_REFERENCES.md`

## Security Note

This repository is for learning internals. For production, prefer authenticated encryption (`AES-GCM`, `ChaCha20-Poly1305`) with strict nonce/key lifecycle management.
