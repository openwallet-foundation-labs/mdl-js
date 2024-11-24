import { CBOR } from '@m-doc/cbor';
import { hkdf } from '@panva/hkdf';
import { areBuffersEqual } from './utils';
import { OrPromise, protectedHeader } from './types';

export type CoseMac0 = [ArrayBuffer, ArrayBuffer, ArrayBuffer, ArrayBuffer];

export const COSE_MAC_ALGORITHMS = {
  'HMAC-SHA-256': 5,
} as const;

type MacGenerator = (
  data: ArrayBuffer,
  key: ArrayBuffer,
) => OrPromise<ArrayBuffer>;

export class CoseMac0Builder {
  // TODO: fix
  async deriveEMacKey(
    ZAB: ArrayBuffer,
    sessionTranscriptBytes: ArrayBuffer,
  ): Promise<Uint8Array> {
    const hash = 'SHA-256';
    const salt = await crypto.subtle.digest('SHA-256', sessionTranscriptBytes);
    const info = new TextEncoder().encode('EMacKey');
    const length = 32; // octets

    return hkdf(hash, new Uint8Array(ZAB), new Uint8Array(salt), info, length);
  }

  private convertHeader(protectedHeader: protectedHeader) {
    const { alg, ...rest } = protectedHeader;
    return {
      '1': COSE_MAC_ALGORITHMS['HMAC-SHA-256'],
      ...rest,
    };
  }

  private createMacStructure(
    protectedHeader: protectedHeader,
    payload: ArrayBuffer,
  ): { macData: ArrayBuffer; encodedProtected: ArrayBuffer } {
    const header = this.convertHeader(protectedHeader);
    const encodedProtected = CBOR.encode(header);

    const MacStructure = [
      'MAC0', // context
      encodedProtected, // body_protected
      new ArrayBuffer(0), // external_aad
      payload, // payload
    ];

    const macData = CBOR.encode(MacStructure);
    return { macData, encodedProtected };
  }

  async mac(
    protectedHeader: protectedHeader,
    unprotectedHeader: Record<string, unknown>,
    deviceAuthenticationBytes: ArrayBuffer,
    ZAB: ArrayBuffer,
    sessionTranscriptBytes: ArrayBuffer,
    macGenerator: MacGenerator,
  ): Promise<ArrayBuffer> {
    const EMacKey = await this.deriveEMacKey(ZAB, sessionTranscriptBytes);

    // payload is null in COSE_Mac0 for mdoc
    const nullPayload = CBOR.encode(null);

    const { macData, encodedProtected } = this.createMacStructure(
      protectedHeader,
      deviceAuthenticationBytes, // detached content
    );

    const tag = await macGenerator(macData, EMacKey);
    const encodedUnprotected = CBOR.encode(unprotectedHeader);

    // CBOR array structure: [protected, unprotected, payload, tag]
    const message: CoseMac0 = [
      encodedProtected,
      encodedUnprotected,
      nullPayload,
      tag,
    ];

    return CBOR.encode(message);
  }
}

export class CoseMac0Verifier {
  async verify(
    message: ArrayBuffer,
    ZAB: ArrayBuffer,
    sessionTranscriptBytes: ArrayBuffer,
    macVerifier: MacGenerator,
  ): Promise<boolean> {
    const [protectedBytes, unprotected, payload, tag] = CBOR.decode(
      message,
    ) as CoseMac0;

    const EMacKey = await new CoseMac0Builder().deriveEMacKey(
      ZAB,
      sessionTranscriptBytes,
    );

    const macStructure = ['MAC0', protectedBytes, new ArrayBuffer(0), payload];
    const macData = CBOR.encode(macStructure);

    const computedTag = await macVerifier(macData, EMacKey);
    return areBuffersEqual(tag, computedTag);
  }
}
