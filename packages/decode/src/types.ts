import { DataElement } from '@m-doc/cbor';
import { IssuerSignedItemParams } from '@m-doc/types';

export type RawMdocData = {
  version: string;
  status: number;
  documents: Array<RawDoc>;
};

export type RawDoc = {
  docType: string;
  issuerSigned: {
    nameSpaces: {
      [name: string]: Array<DataElement<IssuerSignedItemParams<unknown>>>;
    };
    issuerAuth: [Uint8Array, Record<string, unknown>, Uint8Array, Uint8Array];
  };
  deviceSigned?: {
    nameSpaces: DataElement<{ [name: string]: Record<string, unknown> }>;
    deviceAuth: {
      deviceSignature?: [
        Uint8Array,
        Record<string, unknown>,
        Uint8Array,
        Uint8Array,
      ];
      deviceMac?: [Uint8Array, Record<string, unknown>, Uint8Array, Uint8Array];
    };
  };
};
