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
import { Sign1Verifier, Signer } from '@m-doc/cose';
import { DeviceAuth } from './DeviceAuth';

export type issuerSigned = {
  namespaces: Map<string, Array<IssuerSignedItem>>;
  issuerAuth?: IssuerAuth;
};

export type DeviceSigned = {
  namespaces: DataElement<{}>;
  deviceAuth: DeviceAuth;
};

export type IssuerSignedDocumentParams = {
  docType?: string;
  issuerSigned?: issuerSigned;
  deviceSigned?: DeviceSigned;
};

export class IssuerSignedDocument {
  private docType: string;
  private issuerSigned: issuerSigned;
  private deviceSigned?: DeviceSigned;

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

  async validateIssuerAuth(verifier: Sign1Verifier) {
    if (!this.issuerSigned.issuerAuth) {
      throw new Error('IssuerAuth is not set');
    }
    return this.issuerSigned.issuerAuth.verify(verifier);
  }

  public keys() {
    const keys: Record<string, Array<string>> = {};
    this.issuerSigned.namespaces.forEach((value, key) => {
      keys[key] = value.map((item) => item.rawData.elementIdentifier);
    });
    return keys;
  }

  public select(keys: Record<string, Array<string>>) {
    const newNamespaces: Map<string, Array<IssuerSignedItem>> = new Map();
    for (const [name, selectedKeys] of Object.entries(keys)) {
      const namespace = this.issuerSigned.namespaces.get(name);
      if (!namespace) {
        continue;
      }
      const newNamespace = namespace.filter((item) =>
        selectedKeys.includes(item.rawData.elementIdentifier),
      );
      newNamespaces.set(name, newNamespace);
    }

    return new IssuerSignedDocument({
      docType: this.docType,
      issuerSigned: {
        namespaces: newNamespaces,
      },
    });
  }

  serialize() {
    const namespaces = this.serializeNamespace();
    const issuerAuth = this.serializeIssuerAuth();
    if (!this.deviceSigned) {
      return {
        docType: this.docType,
        issuerSigned: {
          namespaces,
          issuerAuth,
        },
      };
    }

    const deviceSigned = this.serializeDeviceSigned();
    return {
      docType: this.docType,
      issuerSigned: {
        namespaces,
        issuerAuth,
      },
      deviceSigned,
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
    if (!this.issuerSigned.issuerAuth) {
      throw new Error('IssuerAuth is not set');
    }
    return this.issuerSigned.issuerAuth.serialize();
  }

  private serializeDeviceSigned() {
    return {
      todo: 'todo',
    };
  }
}
