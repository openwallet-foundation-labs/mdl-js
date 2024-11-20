import { CBOR, copyUint8Array } from './utils';

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
    buffer: ArrayBuffer | Uint8Array,
  ): DataElement<T> {
    const arrayBuffer =
      buffer instanceof Uint8Array ? copyUint8Array(buffer) : buffer.slice(0);
    const data = CBOR.decode<T>(arrayBuffer);
    return new DataElement({ buffer: arrayBuffer, data });
  }
}
