import { CoseKey } from './cose';
import { CBOR } from '@m-doc/cbor';

export type CoseSign1 = [ArrayBuffer, ArrayBuffer, ArrayBuffer, ArrayBuffer];

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
  data: ArrayBuffer,
  key: CoseKey,
  alg: string,
) => OrPromise<ArrayBuffer>;
export type Verifier = (
  data: ArrayBuffer,
  signature: ArrayBuffer,
  option: { alg: string; kid?: string },
) => OrPromise<boolean>;

export class CoseSign1Builder {
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
    payload: ArrayBuffer,
  ): { sig: ArrayBuffer; encodedProtected: ArrayBuffer } {
    const header = this.convertHeader(protectedHeader);
    const encodedProtected = CBOR.encode(header);

    const SigStructure = [
      'Signature1', // context
      encodedProtected, // body_protected
      new ArrayBuffer(0), // external_aad
      payload, // payload
    ];

    const sig = CBOR.encode(SigStructure);
    return { sig, encodedProtected };
  }

  async sign(
    protectedHeader: protectedHeader,
    unprotectedHeader: Record<string, unknown>,
    payload: Record<string, unknown>,
    key: CoseKey,
    signer: Signer,
  ): Promise<ArrayBuffer> {
    const { alg = 'ES256' } = protectedHeader;
    const encodedPayload = CBOR.encode(payload);
    const { sig, encodedProtected } = this.createSigStructure(
      protectedHeader,
      encodedPayload,
    );
    const signature = await signer(sig, key, alg);
    const encodedUnprotected = CBOR.encode(unprotectedHeader);
    // CBOR array structure: [protected, unprotected, payload, signature]
    const message: CoseSign1 = [
      encodedProtected,
      encodedUnprotected,
      encodedPayload,
      signature,
    ];
    return CBOR.encode(message);
  }
}

export class CoseSign1Verifier {
  private algValueToAlg(algValue: number) {
    if (algValue === -7) return 'ES256';
    if (algValue === -35) return 'ES384';
    if (algValue === -36) return 'ES512';
    if (algValue === -8) return 'EDDSA';
    return 'ES256';
  }

  async verify<T extends unknown = unknown>(
    message: ArrayBuffer,
    verifier: Verifier,
  ): Promise<{ verified: boolean; payload: T }> {
    const [protectedBytes, unprotected, payload, signature] = CBOR.decode(
      message,
    ) as CoseSign1;

    const protectedHeader = CBOR.decode<{
      '1': number;
      '4': string | undefined;
    }>(protectedBytes);

    const algValue = protectedHeader['1'] || -7;
    const alg = this.algValueToAlg(algValue);
    const kid = protectedHeader['4'];

    const sigStructure = [
      'Signature1',
      protectedBytes,
      new ArrayBuffer(0),
      payload,
    ];
    const toBeSigned = CBOR.encode(sigStructure);
    const verified = await verifier(toBeSigned, signature, { alg, kid });
    const decodedPayload = CBOR.decode(payload);
    return { verified, payload: decodedPayload as T };
  }
}
