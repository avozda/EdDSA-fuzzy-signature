import {
  derivePrivateKey,
  getPublicKey,
  signMessage,
  verifySignature,
  isValidPrivateKey,
  isValidPublicKey,
} from '../src/crypto.js';
import { randomBytes } from '@noble/hashes/utils.js';

describe('Crypto Utilities', () => {
  describe('derivePrivateKey', () => {
    it('should derive a valid private key from entropy', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(privateKey.length).toBe(32);
      expect(isValidPrivateKey(privateKey)).toBe(true);
    });
    
    it('should produce deterministic keys from same entropy', () => {
      const entropy = randomBytes(32);
      
      const key1 = derivePrivateKey(entropy);
      const key2 = derivePrivateKey(entropy);
      
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(true);
    });
    
    it('should produce different keys from different entropy', () => {
      const entropy1 = randomBytes(32);
      const entropy2 = randomBytes(32);
      
      const key1 = derivePrivateKey(entropy1);
      const key2 = derivePrivateKey(entropy2);
      
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });
    
    it('should produce different keys with different salts', () => {
      const entropy = randomBytes(32);
      const salt1 = new TextEncoder().encode('salt1');
      const salt2 = new TextEncoder().encode('salt2');
      
      const key1 = derivePrivateKey(entropy, salt1);
      const key2 = derivePrivateKey(entropy, salt2);
      
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });
  });
  
  describe('getPublicKey', () => {
    it('should compute packed BabyJubJub public key from private key', async () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = await getPublicKey(privateKey);
      
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(32); // Packed BabyJubJub point
      await expect(isValidPublicKey(publicKey)).resolves.toBe(true);
    });
    
    it('should produce deterministic public keys', async () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      
      const pub1 = await getPublicKey(privateKey);
      const pub2 = await getPublicKey(privateKey);
      
      expect(Buffer.from(pub1).equals(Buffer.from(pub2))).toBe(true);
    });
  });
  
  describe('signMessage and verifySignature', () => {
    it('should sign and verify a message', async () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = await getPublicKey(privateKey);
      
      const message = new TextEncoder().encode('Hello, World!');
      const signature = await signMessage(message, privateKey);
      
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64); // Compact signature format
      
      const isValid = await verifySignature(message, signature, publicKey);
      expect(isValid).toBe(true);
    });
    
    it('should fail verification with wrong message', async () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = await getPublicKey(privateKey);
      
      const message = new TextEncoder().encode('Hello, World!');
      const signature = await signMessage(message, privateKey);
      
      const wrongMessage = new TextEncoder().encode('Hello, Universe!');
      const isValid = await verifySignature(wrongMessage, signature, publicKey);
      
      expect(isValid).toBe(false);
    });
    
    it('should fail verification with wrong public key', async () => {
      const entropy1 = randomBytes(32);
      const entropy2 = randomBytes(32);
      
      const privateKey1 = derivePrivateKey(entropy1);
      const privateKey2 = derivePrivateKey(entropy2);
      const publicKey2 = await getPublicKey(privateKey2);
      
      const message = new TextEncoder().encode('Hello, World!');
      const signature = await signMessage(message, privateKey1);
      
      const isValid = await verifySignature(message, signature, publicKey2);
      expect(isValid).toBe(false);
    });
    
    it('should fail verification with corrupted signature', async () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = await getPublicKey(privateKey);
      
      const message = new TextEncoder().encode('Hello, World!');
      const signature = await signMessage(message, privateKey);
      
      // Corrupt the signature
      const corruptedSignature = new Uint8Array(signature);
      corruptedSignature[0] ^= 0xff;
      
      const isValid = await verifySignature(message, corruptedSignature, publicKey);
      expect(isValid).toBe(false);
    });
    
    it('should produce deterministic signatures', async () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      
      const message = new TextEncoder().encode('Hello, World!');
      
      const sig1 = await signMessage(message, privateKey);
      const sig2 = await signMessage(message, privateKey);
      
      expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(true);
    });
    
    it('should handle empty message', async () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = await getPublicKey(privateKey);
      
      const message = new Uint8Array(0);
      const signature = await signMessage(message, privateKey);
      
      const isValid = await verifySignature(message, signature, publicKey);
      expect(isValid).toBe(true);
    });
    
    it('should handle large message', async () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = await getPublicKey(privateKey);
      
      // Create a message larger than typical (50KB)
      const message = new Uint8Array(50000);
      for (let i = 0; i < 50000; i++) {
        message[i] = i % 256;
      }
      const signature = await signMessage(message, privateKey);
      
      const isValid = await verifySignature(message, signature, publicKey);
      expect(isValid).toBe(true);
    });
  });
  
  describe('isValidPrivateKey', () => {
    it('should return true for valid private key', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      
      expect(isValidPrivateKey(privateKey)).toBe(true);
    });
    
    it('should return false for all-zero key', () => {
      const zeroKey = new Uint8Array(32);
      expect(isValidPrivateKey(zeroKey)).toBe(false);
    });
    
    it('should return false for wrong length', () => {
      const shortKey = randomBytes(16);
      const longKey = randomBytes(64);
      
      expect(isValidPrivateKey(shortKey)).toBe(false);
      expect(isValidPrivateKey(longKey)).toBe(false);
    });
  });
  
  describe('isValidPublicKey', () => {
    it('should return true for valid packed public key', async () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = await getPublicKey(privateKey);
      
      await expect(isValidPublicKey(publicKey)).resolves.toBe(true);
    });
    
    it('should return false for invalid public key', async () => {
      const invalidKey = randomBytes(32);
      await expect(isValidPublicKey(invalidKey)).resolves.toBe(false);
    });
    
    it('should return false for wrong length', async () => {
      const shortKey = randomBytes(16);
      await expect(isValidPublicKey(shortKey)).resolves.toBe(false);
    });
  });
});
