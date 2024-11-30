export const DOC_TYPE = 'org.iso.18013.5.1.mDL';
export const DEFAULT_NAMESPACE = 'org.iso.18013.5.1';

export interface JsonWebKey {
  crv?: string;
  d?: string; // private key
  kty?: string;
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

export type DigestAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';
export type OrPromise<T> = T | Promise<T>;
export type Hasher = (
  data: ArrayBuffer,
  alg: DigestAlgorithm,
) => OrPromise<ArrayBuffer>;
export type RandomGenerator = (length: number) => OrPromise<Uint8Array>;

export enum MDocStatus {
  OK = 0,
  GeneralError = 10,
  CBORDecodingError = 11,
  CBORValidationError = 12,
}

export type DeviceKeyInfo = {
  deviceKey: CoseKey;
};

export type ValidityInfo = {
  signed: Date;
  validFrom: Date;
  validUntil: Date;
  expectedUpdate?: Date;
};

export type MSO = {
  docType: string;
  version: string;
  digestAlgorithm: DigestAlgorithm;
  valueDigests: Map<string, Map<number, ArrayBuffer>>;

  validityInfo: ValidityInfo;
  deviceKeyInfo?: DeviceKeyInfo;
};

export type SessionTranscript = {
  deviceEngagementBytes: ArrayBuffer | null;
  eReaderKeyBytes: ArrayBuffer | null;
  handover: string[];
};

export type IssuerSignedItemParams<T extends unknown = unknown> = {
  digestID: number;
  random: ArrayBuffer;
  elementIdentifier: string;
  elementValue: T;
};
