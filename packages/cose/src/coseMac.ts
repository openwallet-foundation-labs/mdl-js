import { CBOR } from '@m-doc/cbor';
import { OrPromise, protectedHeader } from './types';

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

export type MacVerifier = (
  data: ArrayBuffer,
  tag: ArrayBuffer,
  options: { alg: string; kid?: Uint8Array; certificate?: Uint8Array },
) => OrPromise<boolean>;

export type Mac0Data = {
  protectedHeader: ArrayBuffer;
  unprotectedHeader: Record<string, unknown>;
  payload: ArrayBuffer;
  tag?: ArrayBuffer;
};

export class Mac0 {
  protectedHeader: ArrayBuffer;
  unprotectedHeader: Record<string, unknown>;
  payload: ArrayBuffer;
  tag?: ArrayBuffer;

  constructor(param: Mac0Data) {
    this.protectedHeader = param.protectedHeader;
    this.unprotectedHeader = param.unprotectedHeader;
    this.payload = param.payload;
    this.tag = param.tag;
  }

  static fromBuffer(buffer: ArrayBuffer) {
    const [protectedHeader, unprotectedHeader, payload, tag] =
      CBOR.decode<CoseMac0>(buffer);
    return new Mac0({
      protectedHeader,
      unprotectedHeader,
      payload,
      tag,
    });
  }

  get data(): CoseMac0 {
    return [
      this.protectedHeader,
      this.unprotectedHeader,
      this.payload,
      this.tag ?? new ArrayBuffer(0),
    ];
  }

  get decodedData() {
    return {
      protectedHeader: CBOR.decode(this.protectedHeader),
      unprotectedHeader: this.unprotectedHeader,
      payload: CBOR.decode(this.payload),
      tag: this.tag,
    };
  }

  private getAlgValue(alg: string | undefined) {
    if (!alg) return COSE_MAC_ALGORITHMS['HMAC-SHA-256'];
    if (Object.keys(COSE_MAC_ALGORITHMS).includes(alg))
      return COSE_MAC_ALGORITHMS[alg as keyof typeof COSE_MAC_ALGORITHMS];
    return COSE_MAC_ALGORITHMS['HMAC-SHA-256'];
  }

  private convertHeader(protectedHeader: protectedHeader) {
    const { alg, ...rest } = protectedHeader;
    const algValue = this.getAlgValue(alg);
    return {
      '1': algValue, // alg label is 1 in COSE
      ...rest,
    };
  }

  setProtectedHeader(protectedHeader: protectedHeader) {
    const header = this.convertHeader(protectedHeader);
    const encodedProtected = CBOR.encode(header);
    this.protectedHeader = encodedProtected;
  }

  private createMacStructure() {
    const MacStructure = [
      'MAC0', // context
      this.protectedHeader, // body_protected
      new ArrayBuffer(0), // external_aad
      this.payload, // payload
    ];

    return CBOR.encode(MacStructure);
  }

  async mac(
    key: ArrayBuffer,
    alg: string,
    macFunction: MacFunction,
  ): Promise<ArrayBuffer> {
    const macData = this.createMacStructure();
    const kid = this.unprotectedHeader['4'] as Uint8Array | undefined;
    const tag = await macFunction(macData, key, { alg, kid });

    const message: CoseMac0 = [
      this.protectedHeader,
      this.unprotectedHeader,
      this.payload,
      tag,
    ];
    return CBOR.encode(message);
  }

  private algValueToAlg(algValue: number): string {
    switch (algValue) {
      case 5:
        return 'HMAC-SHA-256';
      case 6:
        return 'HMAC-SHA-384';
      case 7:
        return 'HMAC-SHA-512';
      default:
        return 'HMAC-SHA-256';
    }
  }

  async verify<T extends unknown = unknown>(
    verifyFunction: MacVerifier,
  ): Promise<{ verified: boolean; payload: T }> {
    if (this.tag === undefined) {
      throw new Error('Tag is not set');
    }

    const protectedHeader = CBOR.decode<{ '1': number }>(this.protectedHeader);
    const algValue = protectedHeader['1'] || 5;
    const alg = this.algValueToAlg(algValue);
    const kid = this.unprotectedHeader['4'] as Uint8Array | undefined;
    const certificate = this.unprotectedHeader['33'] as Uint8Array | undefined;

    const macStructure = [
      'MAC0',
      this.protectedHeader,
      new ArrayBuffer(0),
      this.payload,
    ];
    const toBeVerified = CBOR.encode(macStructure);

    const verified = await verifyFunction(toBeVerified, this.tag, {
      alg,
      kid,
      certificate,
    });
    const decodedPayload = CBOR.decode(this.payload);

    return { verified, payload: decodedPayload as T };
  }
}
