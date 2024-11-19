import { describe, expect, test } from 'vitest';
import { DataElement } from '..';

describe('CBOR DataElement', () => {
  test('data', () => {
    const data = { a: 1 };
    const dataElement = DataElement.fromData(data);
    expect(dataElement.data).toStrictEqual(data);
    expect(dataElement.buffer).toBeDefined();
    expect(dataElement.buffer).toBeInstanceOf(ArrayBuffer);

    const buffer = new Uint8Array([0xa1, 0x61, 0x61, 0x01]).buffer;
    expect(dataElement.buffer).toStrictEqual(buffer);
  });

  test('buffer', () => {
    const buffer = new Uint8Array([0xa1, 0x61, 0x61, 0x01]).buffer;
    const dataElement = DataElement.fromBuffer(buffer);
    expect(dataElement.data).toStrictEqual({ a: 1 });
    expect(dataElement.buffer).toBeDefined();
    expect(dataElement.buffer).toBeInstanceOf(ArrayBuffer);
  });

  test('create', () => {
    const data = { a: 1 };
    const buffer = new Uint8Array([0xa1, 0x61, 0x61, 0x01]).buffer;
    const dataElement = new DataElement({ data, buffer });
    expect(dataElement.data).toStrictEqual(data);
    expect(dataElement.buffer).toStrictEqual(buffer);
  });
});
