import { CBOR, DataElement } from '@m-doc/cbor';
import { DeviceSigned, IssuerSignedDocument } from './IssuerSignedDocument';
import { MDocStatus, RawDoc, RawMdocData } from './types';
import { IssuerSignedItem, IssuerSignedItemParams } from './IssuerSignedItem';
import { Mac0, Sign1 } from '@m-doc/cose';
import { IssuerAuth } from './issuerAuth';
import { DeviceAuthMac0, DeviceAuthSign1 } from './DeviceAuth';
import { decodeMdl } from '@m-doc/decode';

export type MDocData = {
  version?: string;
  documents?: IssuerSignedDocument[];
  status?: MDocStatus;
};

export class MDoc {
  public version: string;
  public documents: IssuerSignedDocument[];
  public status: MDocStatus;

  constructor(data: MDocData = {}) {
    this.version = data.version ?? '1.0';
    this.documents = data.documents ?? [];
    this.status = data.status ?? MDocStatus.OK;
  }

  encode() {
    return CBOR.encode({
      version: this.version,
      documents: this.documents.map((doc) => doc.serialize()),
      status: this.status,
    });
  }

  static fromBuffer(buffer: ArrayBuffer) {
    const data = decodeMdl(buffer);
    const { documents, status, version } = data;
    const issuerDocs = documents.map((doc) => {
      const { docType, issuerSigned, deviceSigned } = doc;
      const nameSpaces = parseRawNameSpaces(issuerSigned.nameSpaces);
      const sign1 = new Sign1({
        protectedHeader: issuerSigned.issuerAuth[0],
        unprotectedHeader: issuerSigned.issuerAuth[1],
        payload: issuerSigned.issuerAuth[2],
        signature: issuerSigned.issuerAuth[3],
      });
      const issuerAuth = new IssuerAuth(sign1);

      const deviceSignedClass = parseRawDeviceSigned(deviceSigned);

      const issuerDoc = new IssuerSignedDocument({
        docType,
        issuerSigned: {
          nameSpaces,
          issuerAuth,
        },
        deviceSigned: deviceSignedClass,
      });
      return issuerDoc;
    });

    return new MDoc({
      version,
      documents: issuerDocs,
      status,
    });
  }
}

function parseRawDeviceSigned(
  raw: RawDoc['deviceSigned'],
): DeviceSigned | undefined {
  if (!raw) {
    return undefined;
  }

  const { nameSpaces, deviceAuth } = raw;
  const nameSpacesData = new Map<string, Record<string, unknown>>();
  Object.entries(
    nameSpaces.data as { [name: string]: Record<string, unknown> },
  ).forEach(([name, claims]) => {
    nameSpacesData.set(name, claims);
  });

  if (deviceAuth.deviceSignature) {
    const sign1 = new Sign1({
      protectedHeader: deviceAuth.deviceSignature[0],
      unprotectedHeader: deviceAuth.deviceSignature[1],
      payload: deviceAuth.deviceSignature[2],
      signature: deviceAuth.deviceSignature[3],
    });
    const deviceSignature = new DeviceAuthSign1(sign1);
    return {
      nameSpaces: nameSpacesData,
      deviceAuth: {
        deviceSignature,
      },
    };
  }

  if (deviceAuth.deviceMac) {
    const mac0 = new Mac0({
      protectedHeader: deviceAuth.deviceMac[0],
      unprotectedHeader: deviceAuth.deviceMac[1],
      payload: deviceAuth.deviceMac[2],
      tag: deviceAuth.deviceMac[3],
    });
    const deviceMac = new DeviceAuthMac0(mac0);
    return {
      nameSpaces: nameSpacesData,
      deviceAuth: {
        deviceMac,
      },
    };
  }

  return undefined;
}

function parseRawNameSpaces(raw: { [name: string]: Array<DataElement> }) {
  const nameSpaces: Map<string, Array<IssuerSignedItem>> = new Map();
  Object.entries(raw).forEach(([name, items]) => {
    const issuerSignedItems = items.map(
      (item) =>
        new IssuerSignedItem(
          item as DataElement<IssuerSignedItemParams<unknown>>,
        ),
    );
    nameSpaces.set(name, issuerSignedItems);
  });
  return nameSpaces;
}
