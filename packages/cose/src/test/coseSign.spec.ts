import { describe, expect, test } from 'vitest';
import { Sign1 } from '../index';
import { Sign1 as CoseKitSign1 } from 'cose-kit';
import { subtle } from 'node:crypto';
import { CBOR } from '@m-doc/cbor';
import { importJWK, JWK } from 'jose';

export const ES256 = {
  alg: 'ES256',

  async generateKeyPair() {
    const keyPair = await subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256', // ES256
      },
      true, // whether the key is extractable (i.e., can be used in exportKey)
      ['sign', 'verify'], // can be used to sign and verify signatures
    );

    // Export the public and private keys in JWK format
    const publicKeyJWK = await subtle.exportKey('jwk', keyPair.publicKey);
    const privateKeyJWK = await subtle.exportKey('jwk', keyPair.privateKey);

    return { publicKey: publicKeyJWK, privateKey: privateKeyJWK };
  },

  async getSigner(privateKeyJWK: object) {
    const privateKey = await subtle.importKey(
      'jwk',
      privateKeyJWK,
      {
        name: 'ECDSA',
        namedCurve: 'P-256', // Must match the curve used to generate the key
      },
      true, // whether the key is extractable (i.e., can be used in exportKey)
      ['sign'],
    );

    return async (data: ArrayBuffer) => {
      const signature = await subtle.sign(
        {
          name: 'ECDSA',
          hash: { name: 'SHA-256' }, // Required for ES256
        },
        privateKey,
        data,
      );

      return signature;
    };
  },

  async getVerifier(publicKeyJWK: object) {
    const publicKey = await subtle.importKey(
      'jwk',
      publicKeyJWK,
      {
        name: 'ECDSA',
        namedCurve: 'P-256', // Must match the curve used to generate the key
      },
      true, // whether the key is extractable (i.e., can be used in exportKey)
      ['verify'],
    );

    return async (data: ArrayBuffer, signature: ArrayBuffer) => {
      const isValid = await subtle.verify(
        {
          name: 'ECDSA',
          hash: { name: 'SHA-256' }, // Required for ES256
        },
        publicKey,
        signature,
        data,
      );

      return isValid;
    };
  },
};

describe('COSE', () => {
  test('sign1', async () => {
    const { publicKey, privateKey } = await ES256.generateKeyPair();
    const signer = await ES256.getSigner(privateKey);
    const verifier = await ES256.getVerifier(publicKey);
    const sign1 = new Sign1({
      protectedHeader: CBOR.encode(Sign1.convertHeader({ alg: 'ES256' })),
      unprotectedHeader: { kid: 'key1' },
      payload: CBOR.encode({ foo: 'bar' }),
    });
    const msg = await sign1.sign('ES256', signer);
    expect(msg).toBeDefined();

    const [protectedHeader, unprotectedHeader, payload, signature] = sign1.data;
    expect(protectedHeader).toBeDefined();
    expect(unprotectedHeader).toBeDefined();
    expect(payload).toBeDefined();
    expect(signature).toBeDefined();

    const verify = await sign1.verify(verifier);
    expect(verify.verified).toBe(true);
    expect(verify.payload).toEqual({ foo: 'bar' });
  });
});
