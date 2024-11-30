import { Sign1, Sign1Verifier, Signer } from '@m-doc/cose';
import { MSO } from '@m-doc/types';
import { CBOR, DataElement } from '@m-doc/cbor';

export type IssuerAuthData = {
  alg: string;
  mso: MSO;
  certificate?: Uint8Array;
  unprotectedHeader?: Record<string, unknown>;
};

export class IssuerAuth {
  private sign1: Sign1;
  public mso: DataElement<MSO>;

  constructor(param: IssuerAuthData | Sign1) {
    if (param instanceof Sign1) {
      this.sign1 = param;
      this.mso = DataElement.fromData(param.decodedData.payload);
      return;
    }
    this.mso = DataElement.fromData(param.mso);

    const defaultHeader = CBOR.encode(Sign1.convertHeader({ alg: param.alg }));
    const unprotectedHeader = param.certificate
      ? { '33': param.certificate, ...param.unprotectedHeader }
      : { ...param.unprotectedHeader };

    this.sign1 = new Sign1({
      protectedHeader: defaultHeader,
      unprotectedHeader,
      payload: CBOR.encode(param.mso),
    });
  }

  async sign(alg: string, signer: Signer) {
    return this.sign1.sign(alg, signer);
  }

  async verify(verifier: Sign1Verifier) {
    return this.sign1.verify(verifier);
  }

  serialize() {
    if (this.sign1.signature === undefined) {
      throw new Error('Signature is not set');
    }
    return this.sign1.data;
  }
}
