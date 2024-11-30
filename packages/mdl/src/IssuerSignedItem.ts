import { DataElement } from '@m-doc/cbor';
import { DigestAlgorithm, Hasher, IssuerSignedItemParams } from '@m-doc/types';

export class IssuerSignedItem<T extends unknown = unknown> {
  private dataItem: DataElement<IssuerSignedItemParams<T>>;

  constructor(
    dataItemParam:
      | IssuerSignedItemParams<T>
      | DataElement<IssuerSignedItemParams<T>>,
  ) {
    if (dataItemParam instanceof DataElement) {
      this.dataItem = dataItemParam;
      return;
    }
    this.dataItem = DataElement.fromData(dataItemParam);
  }

  static fromBuffer(buffer: ArrayBuffer) {
    const dataItem = DataElement.fromBuffer<IssuerSignedItemParams>(buffer);
    return new IssuerSignedItem(dataItem.data);
  }

  get data() {
    const value = this.dataItem.data;
    return {
      [value.elementIdentifier]: value.elementValue,
    };
  }

  get rawData() {
    return this.dataItem.data;
  }

  async digest(hasher: Hasher, alg: DigestAlgorithm): Promise<ArrayBuffer> {
    return hasher(this.dataItem.buffer, alg);
  }

  serialize() {
    return this.dataItem;
  }
}
