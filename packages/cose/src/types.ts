export type OrPromise<T> = T | Promise<T>;
export type ProtectedHeader = {
  alg?: string;
  [key: string]: unknown;
};

export const COSE_HEADERS = {
  alg: '1',
  kid: '4',
} as const;

export const COSE_ALGORITHMS = {
  ES256: '-7',
  ES384: '-35',
  ES512: '-36',
  EDDSA: '-8',
} as const;

export type CoseSign1 = [
  ArrayBuffer, // protected header
  Record<string, unknown>, // unprotected header
  ArrayBuffer, // payload
  ArrayBuffer, // signature
];

export type Signer = (
  data: ArrayBuffer,
  option: { alg: string; kid?: Uint8Array },
) => OrPromise<ArrayBuffer>;
export type Sign1Verifier = (
  data: ArrayBuffer,
  signature: ArrayBuffer,
  option: { alg: string; kid?: Uint8Array; certificate?: Uint8Array },
) => OrPromise<boolean>;

export type CoseMac0 = [
  ArrayBuffer, // protected header
  Record<string, unknown>, // unprotected header
  ArrayBuffer, // payload
  ArrayBuffer, // tag
];

export const COSE_MAC_ALGORITHMS = {
  'HMAC-SHA-256': 5,
  'HMAC-SHA-384': 6,
  'HMAC-SHA-512': 7,
} as const;

export type MacFunction = (
  data: ArrayBuffer,
  key: ArrayBuffer,
  options: { alg: string; kid?: Uint8Array },
) => OrPromise<ArrayBuffer>;
