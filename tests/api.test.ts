import { enroll, sign, verify, BiometricSigner, FuzzyExtractionError } from '../src/index.js';
import { randomBytes } from '@noble/hashes/utils.js';

describe('API', () => {
  /**
   * Helper to flip a specified number of bits in a byte array
   */
  function flipBits(data: Uint8Array, numBits: number): Uint8Array {
    const result = new Uint8Array(data);
    const positions = new Set<number>();
    
    while (positions.size < numBits) {
      positions.add(Math.floor(Math.random() * (data.length * 8)));
    }
    
    for (const pos of positions) {
      const byteIndex = Math.floor(pos / 8);
      const bitIndex = pos % 8;
      result[byteIndex] ^= (1 << bitIndex);
    }
    
    return result;
  }

  describe('enroll', () => {
    it('should enroll biometric and return vk and sketch', async () => {
      const biometric = randomBytes(32);
      const { vk, sketch } = await enroll(biometric);
      
      expect(vk).toBeInstanceOf(Uint8Array);
      expect(sketch).toBeInstanceOf(Uint8Array);
      expect(vk.length).toBe(32); // Packed BabyJubJub public key
      expect(sketch.length).toBeGreaterThan(0);
    });
    
    it('should produce different vk for different biometrics', async () => {
      const bio1 = randomBytes(32);
      const bio2 = randomBytes(32);
      
      const result1 = await enroll(bio1);
      const result2 = await enroll(bio2);
      
      expect(Buffer.from(result1.vk).equals(Buffer.from(result2.vk))).toBe(false);
    });
    
    it('should throw for empty biometric', () => {
      const emptyBiometric = new Uint8Array(0);
      return expect(enroll(emptyBiometric)).rejects.toThrow('Biometric input cannot be empty');
    });
    
    it('should handle biometric of different lengths', async () => {
      const shortBio = randomBytes(16);
      const longBio = randomBytes(64);
      
      await expect(enroll(shortBio)).resolves.toBeDefined();
      await expect(enroll(longBio)).resolves.toBeDefined();
    });
  });
  
  describe('sign', () => {
    it('should sign a message with correct biometric', async () => {
      const biometric = randomBytes(32);
      const { sketch } = await enroll(biometric);
      
      const message = new TextEncoder().encode('Test message');
      const signature = await sign(biometric, sketch, message);
      
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
    });
    
    it('should throw FuzzyExtractionError for completely different biometric', async () => {
      const bio1 = randomBytes(32);
      const bio2 = randomBytes(32);
      
      const { sketch } = await enroll(bio1);
      const message = new TextEncoder().encode('Test message');
      
      await expect(sign(bio2, sketch, message)).rejects.toBeInstanceOf(FuzzyExtractionError);
    });
    
    it('should produce deterministic signatures with same inputs', async () => {
      const biometric = randomBytes(32);
      const { sketch } = await enroll(biometric);
      
      const message = new TextEncoder().encode('Test message');
      
      const sig1 = await sign(biometric, sketch, message);
      const sig2 = await sign(biometric, sketch, message);
      
      expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(true);
    });
  });
  
  describe('verify', () => {
    it('should verify a valid signature', async () => {
      const biometric = randomBytes(32);
      const { vk, sketch } = await enroll(biometric);
      
      const message = new TextEncoder().encode('Test message');
      const signature = await sign(biometric, sketch, message);
      
      const isValid = await verify(vk, message, signature);
      expect(isValid).toBe(true);
    });
    
    it('should reject signature with wrong message', async () => {
      const biometric = randomBytes(32);
      const { vk, sketch } = await enroll(biometric);
      
      const message = new TextEncoder().encode('Test message');
      const signature = await sign(biometric, sketch, message);
      
      const wrongMessage = new TextEncoder().encode('Wrong message');
      const isValid = await verify(vk, wrongMessage, signature);
      
      expect(isValid).toBe(false);
    });
    
    it('should reject signature with wrong vk', async () => {
      const bio1 = randomBytes(32);
      const bio2 = randomBytes(32);
      
      const { sketch: sketch1 } = await enroll(bio1);
      const { vk: vk2 } = await enroll(bio2);
      
      const message = new TextEncoder().encode('Test message');
      const signature = await sign(bio1, sketch1, message);
      
      const isValid = await verify(vk2, message, signature);
      expect(isValid).toBe(false);
    });
    
    it('should reject corrupted signature', async () => {
      const biometric = randomBytes(32);
      const { vk, sketch } = await enroll(biometric);
      
      const message = new TextEncoder().encode('Test message');
      const signature = await sign(biometric, sketch, message);
      
      const corruptedSignature = new Uint8Array(signature);
      corruptedSignature[0] ^= 0xff;
      
      const isValid = await verify(vk, message, corruptedSignature);
      expect(isValid).toBe(false);
    });
    
    it('should return false for invalid public key', async () => {
      const invalidVk = randomBytes(32);
      const message = new TextEncoder().encode('Test message');
      const fakeSignature = randomBytes(64);
      
      const isValid = await verify(invalidVk, message, fakeSignature);
      expect(isValid).toBe(false);
    });
  });
  
  describe('Full flow with biometric variation', () => {
    it('should work with identical biometric (same enrollment and signing)', async () => {
      const biometric = randomBytes(32);
      const { vk, sketch } = await enroll(biometric);
      
      const message = new TextEncoder().encode('Hello, World!');
      const signature = await sign(biometric, sketch, message);
      
      await expect(verify(vk, message, signature)).resolves.toBe(true);
    });
    
    it('should fail with completely different biometric', async () => {
      const enrollBiometric = randomBytes(32);
      const differentBiometric = randomBytes(32);
      
      const { sketch } = await enroll(enrollBiometric);
      const message = new TextEncoder().encode('Hello, World!');
      
      // Signing should fail
      await expect(sign(differentBiometric, sketch, message)).rejects.toBeInstanceOf(FuzzyExtractionError);
    });
    
    it('should demonstrate error message for biometric mismatch', async () => {
      const bio1 = randomBytes(32);
      const bio2 = randomBytes(32);
      
      const { sketch } = await enroll(bio1);
      const message = new TextEncoder().encode('Test');
      
      try {
        await sign(bio2, sketch, message);
        fail('Should have thrown FuzzyExtractionError');
      } catch (error) {
        expect(error).toBeInstanceOf(FuzzyExtractionError);
        expect((error as Error).message).toContain('Failed to reproduce key');
      }
    });
  });
  
  describe('BiometricSigner class', () => {
    it('should work like the functional API', async () => {
      const signer = new BiometricSigner();
      const biometric = randomBytes(32);
      
      const { vk, sketch } = await signer.enroll(biometric);
      
      const message = new TextEncoder().encode('Test message');
      const signature = await signer.sign(biometric, sketch, message);
      
      await expect(BiometricSigner.verify(vk, message, signature)).resolves.toBe(true);
    });
    
    it('should support custom configuration', async () => {
      const signer = new BiometricSigner({
        fuzzy: {
          blockSize: 8,
          errorThreshold: 16,
        },
      });
      
      const biometric = randomBytes(32);
      const { vk, sketch } = await signer.enroll(biometric);
      
      const message = new TextEncoder().encode('Test message');
      const signature = await signer.sign(biometric, sketch, message);
      
      await expect(BiometricSigner.verify(vk, message, signature)).resolves.toBe(true);
    });
  });
  
  describe('Edge cases', () => {
    it('should handle empty message', async () => {
      const biometric = randomBytes(32);
      const { vk, sketch } = await enroll(biometric);
      
      const emptyMessage = new Uint8Array(0);
      const signature = await sign(biometric, sketch, emptyMessage);
      
      await expect(verify(vk, emptyMessage, signature)).resolves.toBe(true);
    });
    
    it('should handle large message', async () => {
      const biometric = randomBytes(32);
      const { vk, sketch } = await enroll(biometric);
      
      // Create a large message by concatenating random chunks
      const chunks: Uint8Array[] = [];
      for (let i = 0; i < 10; i++) {
        chunks.push(randomBytes(10000));
      }
      const largeMessage = new Uint8Array(100000);
      let offset = 0;
      for (const chunk of chunks) {
        largeMessage.set(chunk, offset);
        offset += chunk.length;
      }
      
      const signature = await sign(biometric, sketch, largeMessage);
      
      await expect(verify(vk, largeMessage, signature)).resolves.toBe(true);
    });
    
    it('should handle binary message', async () => {
      const biometric = randomBytes(32);
      const { vk, sketch } = await enroll(biometric);
      
      const binaryMessage = new Uint8Array([0x00, 0xff, 0x10, 0xfe, 0x00, 0x00, 0xff]);
      const signature = await sign(biometric, sketch, binaryMessage);
      
      await expect(verify(vk, binaryMessage, signature)).resolves.toBe(true);
    });
    
    it('should maintain consistency across multiple sign operations', async () => {
      const biometric = randomBytes(32);
      const { vk, sketch } = await enroll(biometric);
      
      const messages = [
        new TextEncoder().encode('Message 1'),
        new TextEncoder().encode('Message 2'),
        new TextEncoder().encode('Message 3'),
      ];
      
      const signatures = await Promise.all(messages.map((msg) => sign(biometric, sketch, msg)));
      
      // All signatures should verify
      for (let i = 0; i < messages.length; i++) {
        await expect(verify(vk, messages[i], signatures[i])).resolves.toBe(true);
      }
      
      // Cross-verification should fail
      await expect(verify(vk, messages[0], signatures[1])).resolves.toBe(false);
    });
  });
});
