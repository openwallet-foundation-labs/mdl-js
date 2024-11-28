import * as mdl from '@m-doc/mdl';
import { DOC_TYPE, DEFAULT_NAMESPACE } from '@m-doc/types';
import crypto from 'crypto';
import { ES256 } from './crypto';
import { coseFromJwk } from '@m-doc/cose';

function arrayBufferToHexString(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

const jwkSample = {
  kty: 'EC',
  d: 'KLW1HN6uABbNBqkbAdQwySKMsKjU7MbOzyX4fjggWgY',
  use: 'sig',
  crv: 'P-256',
  x: 'TKb0u9N7eZNIEXQ04Z2O_2yB9-Uw1OonSerLqxNMmfA',
  y: 'GFdvH4e2NHQz40Bgs1jyXZkSbTSj-3SHo-NEVubSwGA',
  alg: 'ES256',
};

function generateRandomBytesSync(length: number) {
  const buffer = crypto.randomBytes(length);
  return new Uint8Array(buffer);
}

function hash(data: ArrayBuffer, alg: string) {
  const hashInstance = crypto.createHash(alg.toLowerCase());
  const buffer = Buffer.from(data);
  hashInstance.update(buffer);
  return hashInstance.digest().buffer;
}

async function test() {
  const { publicKey, privateKey } = await ES256.generateKeyPair();
  const signer = await ES256.getSigner(privateKey);
  const verifier = await ES256.getVerifier(publicKey);

  const isDoc = new mdl.IssuerSignedDocument({
    docType: DOC_TYPE,
  });

  await isDoc.addNamespace(
    DEFAULT_NAMESPACE,
    {
      name: 'Lukas',
      id: '1234',
    },
    generateRandomBytesSync,
  );

  await isDoc.signIssuerAuth(
    { alg: 'ES256', signer },
    { digestAlgorithm: 'SHA-256', hasher: hash },
    {
      signed: new Date(),
      validFrom: new Date(),
      validUntil: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
    },
    {
      deviceKey: coseFromJwk(jwkSample),
    },
    undefined,
    {
      kid: '1234',
    },
  );

  const ret = await isDoc.validateIssuerAuth(verifier);
  console.log(ret);

  await isDoc.addDeviceSignature(
    {
      deviceEngagementBytes: new ArrayBuffer(3),
      eReaderKeyBytes: new ArrayBuffer(5),
      handover: ['handover'],
    },
    { alg: 'ES256', signer },
  );

  const devRet = await isDoc.verifyDeviceSignature(verifier);
  console.log(devRet);

  const a = new mdl.MDoc({
    documents: [isDoc],
  });
  const encodedMdl = a.encode();

  const result = arrayBufferToHexString(encodedMdl);
  console.log(result);
}

test();
