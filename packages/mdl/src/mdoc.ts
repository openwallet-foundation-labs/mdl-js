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

  // encode, decode

  // verify
}
