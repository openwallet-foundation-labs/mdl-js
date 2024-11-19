import { CBOR } from './utils';

export type DataElementParam<T = unknown> = {
  data: T;
  buffer: ArrayBuffer;
};

export class DataElement<T extends unknown = unknown> {
  public readonly data: T;
  public readonly buffer: ArrayBuffer;

  constructor(param: DataElementParam<T>) {
    this.data = param.data;
    this.buffer = param.buffer;
  }

  static fromData<T extends unknown = unknown>(data: T): DataElement<T> {
    const buffer = CBOR.encode(data);
    return new DataElement({ data, buffer });
  }

  static fromBuffer<T extends unknown = unknown>(
    buffer: ArrayBuffer,
  ): DataElement<T> {
    const data = CBOR.decode(buffer);
    return new DataElement({ data, buffer });
  }
}
