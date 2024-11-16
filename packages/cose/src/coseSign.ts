import {
  CBORDecoder,
  CBOREncoder,
  TextDecoder,
  TextEncoder,
} from '@m-doc/cbor';
import { CoseKey } from './cose';

export type CoseSign1 = [Uint8Array, Uint8Array, Uint8Array, Uint8Array];

export type protectedHeader = {
  alg?: string;
  kid?: string;
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

export type OrPromise<T> = T | Promise<T>;
export type Signer = (
  data: Uint8Array,
  key: CoseKey,
  alg: string,
) => OrPromise<Uint8Array>;
export type Verifier = (
  data: Uint8Array,
  signature: Uint8Array,
  option: { alg: string; kid?: string },
) => OrPromise<boolean>;

export class CoseSign1Builder {
  private cborEncoder: CBOREncoder;
  constructor(textEncoder: TextEncoder) {
    this.cborEncoder = new CBOREncoder(textEncoder);
  }

  private getAlgValue(alg: string | undefined) {
    if (!alg) return COSE_ALGORITHMS.ES256;
    if (Object.keys(COSE_ALGORITHMS).includes(alg))
      return COSE_ALGORITHMS[alg as keyof typeof COSE_ALGORITHMS];
    return COSE_ALGORITHMS.ES256;
  }

  private convertHeader(protectedHeader: protectedHeader) {
    const { alg, kid, ...rest } = protectedHeader;
    const algValue = this.getAlgValue(alg);
    const kidValue = kid ? { '4': kid } : {};
    return {
      '1': algValue,
      ...kidValue,
      ...rest,
    };
  }

  private createSigStructure(
    protectedHeader: protectedHeader,
    payload: Uint8Array,
  ): { sig: Uint8Array; encodedProtected: Uint8Array } {
    const header = this.convertHeader(protectedHeader);
    const encodedProtected = this.cborEncoder.encode(header);

    const SigStructure = [
      'Signature1', // context
      encodedProtected, // body_protected
      new Uint8Array(0), // external_aad
      payload, // payload
    ];

    const sig = this.cborEncoder.encode(SigStructure);
    return { sig, encodedProtected };
  }

  async sign(
    protectedHeader: protectedHeader,
    unprotectedHeader: Record<string, unknown>,
    payload: Record<string, unknown>,
    key: CoseKey,
    signer: Signer,
  ): Promise<Uint8Array> {
    const { alg = 'ES256' } = protectedHeader;
    const encodedPayload = this.cborEncoder.encode(payload);
    const { sig, encodedProtected } = this.createSigStructure(
      protectedHeader,
      encodedPayload,
    );
    const signature = await signer(sig, key, alg);
    const encodedUnprotected = this.cborEncoder.encode(unprotectedHeader);
    // CBOR array structure: [protected, unprotected, payload, signature]
    const message: CoseSign1 = [
      encodedProtected,
      encodedUnprotected,
      encodedPayload,
      signature,
    ];
    return this.cborEncoder.encode(message);
  }
}

export class CoseSign1Verifier {
  private cborEncoder: CBOREncoder;
  private cborDecoder: CBORDecoder;
  constructor(textEncoder: TextEncoder, textDecoder: TextDecoder) {
    this.cborEncoder = new CBOREncoder(textEncoder);
    this.cborDecoder = new CBORDecoder(textDecoder);
  }

  private algValueToAlg(algValue: number) {
    if (algValue === -7) return 'ES256';
    if (algValue === -35) return 'ES384';
    if (algValue === -36) return 'ES512';
    if (algValue === -8) return 'EDDSA';
    return 'ES256';
  }

  async verify<T extends unknown = unknown>(
    message: Uint8Array,
    verifier: Verifier,
  ): Promise<{ verified: boolean; payload: T }> {
    const [protectedBytes, unprotected, payload, signature] =
      this.cborDecoder.decode(message) as CoseSign1;

    const protectedHeader = this.cborDecoder.decode<{
      '1': number;
      '4': string | undefined;
    }>(protectedBytes);

    const algValue = protectedHeader['1'] || -7;
    const alg = this.algValueToAlg(algValue);
    const kid = protectedHeader['4'];

    const sigStructure = [
      'Signature1',
      protectedBytes,
      new Uint8Array(0),
      payload,
    ];
    const toBeSigned = this.cborEncoder.encode(sigStructure);
    const verified = await verifier(toBeSigned, signature, { alg, kid });
    const decodedPayload = this.cborDecoder.decode(payload);
    return { verified, payload: decodedPayload as T };
  }
}
