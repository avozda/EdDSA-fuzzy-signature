/**
 * Cryptographic utilities for BabyJubJub EdDSA with Poseidon.
 */

import { buildEddsa } from "circomlibjs";
import { sha256 } from "@noble/hashes/sha256.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { KEY_LENGTH } from "./types.js";

const PRIVATE_KEY_INFO = "eddsa-babyjubjub-poseidon-key";
const SUB_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

let eddsaPromise: Promise<any> | null = null;

function getEddsa(): Promise<any> {
  if (!eddsaPromise) {
    eddsaPromise = buildEddsa();
  }
  return eddsaPromise;
}

/**
 * Derives a BabyJubJub private key seed from raw entropy using HKDF.
 */
export function derivePrivateKey(
  entropy: Uint8Array,
  salt: Uint8Array = new Uint8Array(0)
): Uint8Array {
  return hkdf(sha256, entropy, salt, PRIVATE_KEY_INFO, KEY_LENGTH);
}

/**
 * Computes a packed BabyJubJub public key from a private key seed.
 */
export async function getPublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  const eddsa = await getEddsa();
  const pub = eddsa.prv2pub(privateKey);
  return eddsa.babyJub.packPoint(pub);
}

/**
 * Signs a message using BabyJubJub EdDSA Poseidon.
 */
export async function signMessage(
  message: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  const eddsa = await getEddsa();
  const msgField = messageToFieldElement(message);
  const signature = eddsa.signPoseidon(privateKey, msgField);
  return eddsa.packSignature(signature);
}

/**
 * Verifies a BabyJubJub EdDSA Poseidon signature.
 */
export async function verifySignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    const eddsa = await getEddsa();
    const pub = eddsa.babyJub.unpackPoint(new Uint8Array(publicKey));
    if (!pub || !eddsa.babyJub.inCurve(pub)) {
      return false;
    }
    const unpackedSignature = eddsa.unpackSignature(signature);
    if (!unpackedSignature.R8 || !eddsa.babyJub.inCurve(unpackedSignature.R8)) {
      return false;
    }

    const msgField = messageToFieldElement(message);
    return eddsa.verifyPoseidon(msgField, unpackedSignature, pub);
  } catch {
    return false;
  }
}

/**
 * Converts a byte array to a bigint (big-endian).
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Validates that a byte array represents a valid BabyJubJub private key seed.
 *
 * @param key - Byte array to validate
 * @returns true if key is valid, false otherwise
 */
export function isValidPrivateKey(key: Uint8Array): boolean {
  if (!(key instanceof Uint8Array) || key.length !== KEY_LENGTH) {
    return false;
  }

  const keyNum = bytesToBigInt(key);
  if (keyNum === 0n) {
    return false;
  }

  return keyNum < (1n << 256n);
}

/**
 * Validates that a byte array represents a valid packed BabyJubJub public key.
 */
export async function isValidPublicKey(key: Uint8Array): Promise<boolean> {
  if (!(key instanceof Uint8Array) || key.length !== KEY_LENGTH) {
    return false;
  }

  try {
    const eddsa = await getEddsa();
    const point = eddsa.babyJub.unpackPoint(new Uint8Array(key));
    return !!point && eddsa.babyJub.inCurve(point) && eddsa.babyJub.inSubgroup(point);
  } catch {
    return false;
  }
}

function messageToFieldElement(message: Uint8Array): Uint8Array {
  const digest = sha256(message);
  const reduced = bytesToBigIntLE(digest) % SUB_ORDER;
  return bigIntToBytesLE(reduced, KEY_LENGTH);
}

function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

function bigIntToBytesLE(value: bigint, length: number): Uint8Array {
  const result = new Uint8Array(length);
  let temp = value;
  for (let i = 0; i < length; i++) {
    result[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return result;
}
