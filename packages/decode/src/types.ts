import { DataElement } from '@m-doc/cbor';

export type RawMdocData = {
  version: string;
  status: number;
  documents: Array<RawDoc>;
};

export type RawDoc = {
  docType: string;
  issuerSigned: {
    nameSpaces: {
      [name: string]: Array<DataElement>;
    };
    issuerAuth: [Uint8Array, Record<string, unknown>, Uint8Array, Uint8Array];
  };
  deviceSigned?: {
    nameSpaces: DataElement;
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
