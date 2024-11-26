import { CoseKey } from '@m-doc/cose';

export type DigestAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';
export type OrPromise<T> = T | Promise<T>;
export type Hasher = (
  data: ArrayBuffer,
  alg: DigestAlgorithm,
) => OrPromise<ArrayBuffer>;
export type RandomGenerator = () => OrPromise<Uint8Array>;

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
