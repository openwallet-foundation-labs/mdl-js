import { Mac0, MacFunction, Sign1, Sign1Verifier, Signer } from '@m-doc/cose';
import { SessionTranscript } from '@m-doc/types';
import { CBOR, DataElement } from '@m-doc/cbor';

export interface DeviceAuthParams {
  alg: string;
  sessionTranscript: SessionTranscript;
  docType: string;
  namespaces: Map<string, Record<string, unknown>>;
  unprotectedHeader?: Record<string, unknown>;
}

export class DeviceAuthMac0 {
  private deviceMac?: Mac0;

  constructor(params: DeviceAuthParams | Mac0) {
    if (params instanceof Mac0) {
      this.deviceMac = params;
      return;
    }
    const defaultHeader = CBOR.encode(Mac0.convertHeader({ alg: params.alg }));

    this.deviceMac = new Mac0({
      protectedHeader: defaultHeader,
      unprotectedHeader: { ...params.unprotectedHeader },
      payload: calculateDeviceAuthBytes(
        params.sessionTranscript,
        params.docType,
        params.namespaces,
      ),
    });
  }

  async mac(pubKey: ArrayBuffer, alg: string, macFunction: MacFunction) {
    if (!this.deviceMac) {
      throw new Error('DeviceMac is not set');
    }
    return this.deviceMac.mac(pubKey, alg, macFunction);
  }

  async verify(pubKey: ArrayBuffer, macFunction: MacFunction) {
    if (!this.deviceMac) {
      throw new Error('DeviceMac is not set');
    }
    return this.deviceMac.verify(pubKey, macFunction);
  }

  serialize() {
    if (this.deviceMac === undefined) {
      throw new Error('DeviceMac is not set');
    }
    return this.deviceMac.data;
  }
}

export class DeviceAuthSign1 {
  private deviceSign: Sign1;

  constructor(params: DeviceAuthParams | Sign1) {
    if (params instanceof Sign1) {
      this.deviceSign = params;
      return;
    }

    const defaultHeader = CBOR.encode(Sign1.convertHeader({ alg: params.alg }));

    this.deviceSign = new Sign1({
      protectedHeader: defaultHeader,
      unprotectedHeader: { ...params.unprotectedHeader },
      payload: calculateDeviceAuthBytes(
        params.sessionTranscript,
        params.docType,
        params.namespaces,
      ),
    });
  }

  public async sign(alg: string, signer: Signer) {
    if (!this.deviceSign) {
      throw new Error('DeviceSign is not set');
    }

    return this.deviceSign.sign(alg, signer);
  }

  public async verifySign(verifier: Sign1Verifier) {
    if (!this.deviceSign) {
      throw new Error('DeviceSign is not set');
    }
    return this.deviceSign.verify(verifier);
  }

  serialize() {
    if (this.deviceSign === undefined) {
      throw new Error('DeviceSign is not set');
    }
    return this.deviceSign.data;
  }
}

function calculateDeviceAuthBytes(
  sessionTranscript: SessionTranscript,
  docType: string,
  namespaces: Map<string, Record<string, unknown>>,
) {
  const sessionTranscriptData = [
    sessionTranscript.deviceEngagementBytes,
    sessionTranscript.eReaderKeyBytes,
    sessionTranscript.handover,
  ];

  const encode = DataElement.fromData([
    'DeviceAuthentication',
    sessionTranscriptData,
    docType,
    DataElement.fromData(namespaces),
  ]);

  return encode.buffer;
}
