import { CBOR } from '@m-doc/cbor';
import { IssuerSignedDocument } from './IssuerSignedDocument';
import { MDocStatus } from './types';

export type MDocData = {
  version?: string;
  documents?: IssuerSignedDocument[];
  status?: MDocStatus;
};

export class MDoc {
  public version;
  public documents: IssuerSignedDocument[];
  public status: MDocStatus;

  constructor(data: MDocData = {}) {
    this.version = data.version ?? '1.0';
    this.documents = data.documents ?? [];
    this.status = data.status ?? MDocStatus.OK;
  }

  encode() {
    CBOR.encode({
      version: this.version,
      documents: this.documents.map((doc) => doc.serialize()),
      status: this.status,
    });
  }

  static fromBuffer(buffer: ArrayBuffer) {
    // TODO: fix
    const data = CBOR.decode<MDocData>(buffer);
    return new MDoc(data);
  }
}
