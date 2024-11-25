import { DataElement } from '@m-doc/cbor';
import { IssuerSignedItem, IssuerSignedItemParams } from './IssuerSignedItem';
import { RandomGenerator } from './types';

export type issuerSigned = {
  namespaces: Map<string, Array<IssuerSignedItem>>;
  issuerAuth?: any;
};

export type IssuerSignedDocumentParams = {
  docType?: string;
  issuerSigned?: issuerSigned;
  deviceSigned?: any;
};

export class IssuerSignedDocument {
  private docType: string;
  private issuerSigned: issuerSigned;
  private deviceSigned: any;

  constructor(params: IssuerSignedDocumentParams) {
    this.docType = params.docType || 'org.iso.18013.5.1.mDL';
    this.issuerSigned = params.issuerSigned ?? {
      namespaces: new Map<string, Array<IssuerSignedItem>>(),
    };
    this.deviceSigned = params.deviceSigned;
  }

  async addNamespace(
    name: string,
    claims: Record<string, unknown>,
    randomGenerator: RandomGenerator,
  ) {
    const promises = Object.entries(claims).map(
      async ([key, value], idx: number) => {
        const random = await randomGenerator();
        const issuerSignedItem = new IssuerSignedItem({
          digestID: idx,
          random,
          elementIdentifier: key,
          elementValue: value,
        });
        return issuerSignedItem;
      },
    );
    const namespace = await Promise.all(promises);
    this.issuerSigned.namespaces.set(name, namespace);
  }

  async namespaceFromDataElement(
    name: string,
    dataElements: Array<DataElement>,
  ) {
    const issuerSignedItems = dataElements.map((de) => {
      const item = new IssuerSignedItem(
        de as DataElement<IssuerSignedItemParams<unknown>>,
      );
      return item;
    });
    this.issuerSigned.namespaces.set(name, issuerSignedItems);
  }

  serialize() {
    return {
      docType: this.docType,
      issuerSigned: {
        namespaces: this.serializeNamespace(),
        issuerAuth: this.serializeIssuerAuth(),
      },
      deviceSigned: this.serializeDeviceSigned(),
    };
  }

  private serializeNamespace() {
    const map = new Map<string, Array<DataElement>>();
    for (const [name, namespace] of this.issuerSigned.namespaces.entries()) {
      const serializedNamespace = namespace.map((item) => item.serialize());
      map.set(name, serializedNamespace);
    }
    return map;
  }

  private serializeIssuerAuth() {
    return {
      todo: 'todo',
    };
  }

  private serializeDeviceSigned() {
    return {
      todo: 'todo',
    };
  }

  // MUST, from data and from buffer

  // namespace manange, add delete.

  // sign
}
