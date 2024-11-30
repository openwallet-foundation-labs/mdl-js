import { subtle } from 'node:crypto';
import crypto from 'crypto';

export function arrayBufferToHexString(buffer: ArrayBuffer) {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export const jwkSample = {
  kty: 'EC',
  d: 'KLW1HN6uABbNBqkbAdQwySKMsKjU7MbOzyX4fjggWgY',
  use: 'sig',
  crv: 'P-256',
  x: 'TKb0u9N7eZNIEXQ04Z2O_2yB9-Uw1OonSerLqxNMmfA',
  y: 'GFdvH4e2NHQz40Bgs1jyXZkSbTSj-3SHo-NEVubSwGA',
  alg: 'ES256',
};

export function generateRandomBytesSync(length: number) {
  const buffer = crypto.randomBytes(length);
  return new Uint8Array(buffer);
}

export function hash(data: ArrayBuffer, alg: string) {
  const hashInstance = crypto.createHash(alg.toLowerCase());
  const buffer = Buffer.from(data);
  hashInstance.update(buffer);
  return hashInstance.digest().buffer;
}

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
