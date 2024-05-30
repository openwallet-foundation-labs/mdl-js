import { concat } from '@mdoc/cbor';
import { base64urlToUint8Array, uint8ArrayToBase64Url } from './base64url';

export interface JsonWebKey {
  alg?: string;
  crv?: string;
  d?: string; // private key
  ext?: boolean;
  key_ops?: string[];
  kty?: string;
  use?: string;
  x: string; // public key
  y: string; // public key
}

export interface CoseKey {
  '1': number; // key type (EC2: 2)
  '-1': number; // curve (1: P-256, 2: P-384, 3: P-521)
  '-2': Uint8Array; // x
  '-3': Uint8Array; // y
  '-4'?: Uint8Array; // private key
}

export const coseToJwk = (coseKey: CoseKey): JsonWebKey => {
  const kty = coseKey['1'];
  if (kty !== 2) {
    throw new Error(`Expected COSE Key type: EC2 (2), got: ${kty}`);
  }

  const crvMap: Record<number, string> = {
    1: 'P-256',
    2: 'P-384',
    3: 'P-521',
  };

  const crv = coseKey['-1'];
  const x = coseKey['-2'];
  const y = coseKey['-3'];
  const d = coseKey['-4'];

  const jwk: JsonWebKey = {
    kty: 'EC',
    crv: crvMap[crv],
    x: uint8ArrayToBase64Url(x),
    y: uint8ArrayToBase64Url(y),
  };

  if (d) {
    jwk.d = uint8ArrayToBase64Url(d);
  }

  return jwk;
};

export const coseFromJwk = (jwk: JsonWebKey): CoseKey => {
  if (jwk.kty !== 'EC') {
    throw new Error(`Expected JWK Key type: EC, got: ${jwk.kty}`);
  }

  const crvMap: Record<string, number> = {
    'P-256': 1,
    'P-384': 2,
    'P-521': 3,
  };

  const crv: number | undefined = crvMap[jwk.crv ?? ''];
  if (!crv) {
    throw new Error(`Unsupported curve: ${jwk.crv}`);
  }

  const coseKey: CoseKey = {
    '1': 2,
    '-1': crv,
    '-2': base64urlToUint8Array(jwk.x),
    '-3': base64urlToUint8Array(jwk.y),
  };

  if (jwk.d) {
    coseKey['-4'] = base64urlToUint8Array(jwk.d);
  }

  return coseKey;
};

export const coseToBuffer = (key: CoseKey): Uint8Array => {
  const kty = key['1'];
  if (kty !== 2) {
    throw new Error(`Expected COSE Key type: EC2 (2), got: ${kty}`);
  }

  if (key['-4']) {
    // if private key is present, return the private key
    return key['-4'];
  }

  // return public key
  return concat(Uint8Array.from([0x04]), key['-2'], key['-3']);
};
