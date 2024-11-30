import crypto, { subtle } from 'node:crypto';

export function generateRandomBytesSync(length: number) {
  const buffer = crypto.randomBytes(length);
  return new Uint8Array(buffer);
}

export function hash(data: ArrayBuffer, alg: string) {
  const hashInstance = crypto.createHash(alg.toLowerCase());
  const buffer = new Uint8Array(data);
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
