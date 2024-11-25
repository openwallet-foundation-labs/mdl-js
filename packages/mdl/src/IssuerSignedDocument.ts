import { DataElement } from '@m-doc/cbor';
import { IssuerSignedItem, IssuerSignedItemParams } from './IssuerSignedItem';
import {
  DeviceKeyInfo,
  DigestAlgorithm,
  Hasher,
  MSO,
  RandomGenerator,
  ValidityInfo,
} from './types';
import { IssuerAuth } from './issuerAuth';
import { Signer } from '@m-doc/cose';

export type issuerSigned = {
  namespaces: Map<string, Array<IssuerSignedItem>>;
  issuerAuth?: IssuerAuth;
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

  async calculateValueDigest(hasher: Hasher, digestAlgorithm: DigestAlgorithm) {
    const valueDigests: Map<string, Map<number, ArrayBuffer>> = new Map();
    this.issuerSigned.namespaces.forEach(async (namespace, name) => {
      const promises = namespace.map(async (item) => {
        const digest = await item.digest(hasher, digestAlgorithm);
        return digest;
      });
      const digests = await Promise.all(promises);
      const map = new Map<number, ArrayBuffer>();
      digests.forEach((digest, idx) => {
        map.set(idx, digest);
      });
      valueDigests.set(name, map);
    });
    return valueDigests;
  }

  async signIssuerAuth(
    signerFunc: { alg: string; signer: Signer },
    hasherFunc: { digestAlgorithm: DigestAlgorithm; hasher: Hasher },
    validityInfo: ValidityInfo,
    deviceKeyInfo?: DeviceKeyInfo,
    certificate?: Uint8Array,
  ) {
    const valueDigests = await this.calculateValueDigest(
      hasherFunc.hasher,
      hasherFunc.digestAlgorithm,
    );
    const mso: MSO = {
      docType: this.docType,
      version: '1.0',
      digestAlgorithm: hasherFunc.digestAlgorithm,
      valueDigests,
      validityInfo,
      deviceKeyInfo,
    };

    const issuerAuth = new IssuerAuth({ mso, certificate });
    return issuerAuth.sign(signerFunc.alg, signerFunc.signer);
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
