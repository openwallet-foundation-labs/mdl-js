import { CBOR, copyUint8Array } from '@m-doc/cbor';
import {
  COSE_ALGORITHMS,
  CoseSign1,
  ProtectedHeader,
  Sign1Verifier,
  Signer,
} from './types';

export type Sign1Data = {
  protectedHeader: ArrayBuffer;
  unprotectedHeader: Record<string, unknown>;
  payload: ArrayBuffer;
  signature?: ArrayBuffer;
};

export class Sign1 {
  protectedHeader: ArrayBuffer;
  unprotectedHeader: Record<string, unknown>;
  payload: ArrayBuffer;
  signature?: ArrayBuffer;

  constructor(param: Sign1Data) {
    this.protectedHeader = param.protectedHeader;
    this.unprotectedHeader = param.unprotectedHeader;
    this.payload = param.payload;
    this.signature = param.signature;
  }

  static fromBuffer(buffer: ArrayBuffer) {
    const [protectedHeader, unprotectedHeader, payload, signature] =
      CBOR.decode(buffer);
    return new Sign1({
      protectedHeader: copyUint8Array(protectedHeader),
      unprotectedHeader,
      payload: copyUint8Array(payload),
      signature: copyUint8Array(signature),
    });
  }

  get data(): CoseSign1 {
    return [
      this.protectedHeader,
      this.unprotectedHeader,
      this.payload,
      this.signature ?? new ArrayBuffer(0),
    ];
  }

  get decodedData() {
    return {
      protectedHeader: CBOR.decode(this.protectedHeader),
      unprotectedHeader: this.unprotectedHeader,
      payload: CBOR.decode(this.payload),
      signature: this.signature,
    };
  }

  static getAlgValue(alg: string | undefined) {
    if (!alg) return COSE_ALGORITHMS.ES256;
    if (Object.keys(COSE_ALGORITHMS).includes(alg))
      return COSE_ALGORITHMS[alg as keyof typeof COSE_ALGORITHMS];
    return COSE_ALGORITHMS.ES256;
  }

  static convertHeader(protectedHeader: ProtectedHeader) {
    const { alg, ...rest } = protectedHeader;
    const algValue = Sign1.getAlgValue(alg);
    return {
      '1': algValue,
      ...rest,
    };
  }

  setProtectedHeader(protectedHeader: ProtectedHeader) {
    const header = Sign1.convertHeader(protectedHeader);
    const encodedProtected = CBOR.encode(header);
    this.protectedHeader = encodedProtected;
  }

  private createSigStructure() {
    const SigStructure = [
      'Signature1', // context
      this.protectedHeader, // body_protected
      new ArrayBuffer(0), // external_aad
      this.payload, // payload
    ];

    const sig = CBOR.encode(SigStructure);
    return sig;
  }

  async sign(alg: string, signer: Signer): Promise<ArrayBuffer> {
    const sig = this.createSigStructure();
    const kid = this.unprotectedHeader['4'] as Uint8Array | undefined;
    const signature = await signer(sig, { alg, kid });
    this.signature = signature;
    // CBOR array structure: [protected, unprotected, payload, signature]
    const message: CoseSign1 = [
      this.protectedHeader,
      this.unprotectedHeader,
      this.payload,
      signature,
    ];
    return CBOR.encode(message);
  }

  private algValueToAlg(algValue: number) {
    if (algValue === -7) return 'ES256';
    if (algValue === -35) return 'ES384';
    if (algValue === -36) return 'ES512';
    if (algValue === -8) return 'EDDSA';
    return 'ES256';
  }

  async verify<T extends unknown = unknown>(
    verifier: Sign1Verifier,
  ): Promise<{ verified: boolean; payload: T }> {
    if (this.signature === undefined) {
      throw new Error('Signature is not set');
    }
    const protectedHeader = CBOR.decode<{
      '1': number;
    }>(this.protectedHeader);

    const algValue = protectedHeader['1'] || -7;
    const alg = this.algValueToAlg(algValue);
    const kid = this.unprotectedHeader['4'] as Uint8Array | undefined;
    const certificate = this.unprotectedHeader['33'] as Uint8Array | undefined;

    const sigStructure = [
      'Signature1',
      this.protectedHeader,
      new ArrayBuffer(0),
      this.payload,
    ];
    const toBeSigned = CBOR.encode(sigStructure);
    const verified = await verifier(toBeSigned, this.signature, {
      alg,
      kid,
      certificate,
    });
    const decodedPayload = CBOR.decode(this.payload);
    return { verified, payload: decodedPayload as T };
  }
}
