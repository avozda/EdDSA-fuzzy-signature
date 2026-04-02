# eddsa-fuzzy-signature

A TypeScript library for biometric-based digital signatures using fuzzy extractors and BabyJubJub EdDSA Poseidon.

This major version migrates from ECDSA/secp256k1 to BabyJubJub EdDSA with Poseidon hashing.

## Overview

The library treats biometric input as an opaque `Uint8Array` of fixed length. The caller is responsible for feature extraction, normalization, and producing stable byte vectors.

The library provides:
- Fuzzy extraction to derive stable cryptographic key material from noisy biometrics
- BabyJubJub EdDSA-Poseidon key derivation, signing, and verification
- Stateless signature verification with only the public verification key

## Important Breaking Changes in v2

- Signature scheme changed to BabyJubJub EdDSA Poseidon.
- Verification key format changed to packed BabyJubJub points (`32` bytes).
- API methods `enroll`, `sign`, and `verify` are now async.
- Existing keys/signatures from previous ECDSA versions are not compatible.

## Installation

```bash
npm install eddsa-fuzzy-signature
```

## Usage

```typescript
import { enroll, sign, verify } from "eddsa-fuzzy-signature";

async function demo() {
  const biometric = new Uint8Array(32);

  const { vk, sketch } = await enroll(biometric);

  const message = new TextEncoder().encode("Hello, World!");
  const signature = await sign(biometric, sketch, message);

  const isValid = await verify(vk, message, signature);
  console.log("Signature valid:", isValid);
}
```

## API

### `enroll(b: Uint8Array, config?: SignerConfig): Promise<EnrollmentResult>`

Enrolls biometric input, returning:
- `vk`: packed BabyJubJub public key (`Uint8Array`, 32 bytes)
- `sketch`: fuzzy extractor helper data

### `sign(b: Uint8Array, sketch: Uint8Array, message: Uint8Array): Promise<Uint8Array>`

Signs a message with BabyJubJub EdDSA Poseidon after reproducing key material from biometric input and sketch.

- Returns packed signature (`Uint8Array`, 64 bytes)
- Throws `FuzzyExtractionError` on biometric mismatch

### `verify(vk: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean>`

Verifies a BabyJubJub EdDSA Poseidon signature.

## Security Notes

- The security of derived keys depends on biometric min-entropy and preprocessing quality.
- Sketches leak bounded information and must be stored securely.
- Poseidon signing is over a field element; this library deterministically maps message bytes to a field element via SHA-256 and subgroup reduction.

## Development

```bash
npm install
npm test
npm run build
```

## License

GPL-3.0
