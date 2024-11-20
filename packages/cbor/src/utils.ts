import { encode, decode, TaggedValue } from 'cbor-redux';
import { DataElement } from './DataElement';

const encodeCBOR = <T = any>(data: T): ArrayBuffer =>
  encode(data, (key, value) => {
    if (value instanceof DataElement) return new TaggedValue(value.buffer, 24);
    if (value instanceof Date) {
      // According to ISO 23220-2, Date objects should be serialized as ISO 8601 strings with tag 0 (tdate = #6.0(tstr))
      return new TaggedValue(value.toISOString(), 0);
    }
    return value;
  });

const decodeCBOR = <T = any>(buffer: ArrayBuffer): T =>
  decode(buffer, (key, value) => {
    if (value instanceof TaggedValue && value.tag === 24)
      return DataElement.fromBuffer(value.value);
    if (value instanceof TaggedValue && value.tag === 0) {
      return new Date(value.value);
    }
    return value;
  });

export const CBOR = {
  encode: encodeCBOR,
  decode: decodeCBOR,
};

export const copyUint8Array = (buffer: Uint8Array): ArrayBuffer => {
  return buffer.buffer.slice(
    buffer.byteOffset,
    buffer.byteOffset + buffer.byteLength,
  );
};
