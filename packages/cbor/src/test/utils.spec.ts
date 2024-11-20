import { describe, expect, test } from 'vitest';
import { CBOR } from '../utils';
import { DataElement } from '../DataElement';

describe('CBOR utils', () => {
  test('encode/decode numbers', () => {
    const testCases = [42, 0, -1, 1.5];
    for (const testCase of testCases) {
      const encoded = CBOR.encode(testCase);
      const decoded = CBOR.decode(encoded);
      expect(decoded).toEqual(testCase);
    }
  });

  test('encode/decode strings', () => {
    const testCases = ['hello world', ''];
    for (const testCase of testCases) {
      const encoded = CBOR.encode(testCase);
      const decoded = CBOR.decode(encoded);
      expect(decoded).toEqual(testCase);
    }
  });

  test('encode/decode booleans', () => {
    const testCases = [true, false];
    for (const testCase of testCases) {
      const encoded = CBOR.encode(testCase);
      const decoded = CBOR.decode(encoded);
      expect(decoded).toEqual(testCase);
    }
  });

  test('encode/decode null', () => {
    const testCase = null;
    const encoded = CBOR.encode(testCase);
    const decoded = CBOR.decode(encoded);
    expect(decoded).toEqual(testCase);
  });

  test('encode/decode arrays', () => {
    const testCases = [[1, 2, 3], []];
    for (const testCase of testCases) {
      const encoded = CBOR.encode(testCase);
      const decoded = CBOR.decode(encoded);
      expect(decoded).toEqual(testCase);
    }
  });

  test('encode/decode objects', () => {
    const testCases = [{ a: 1, b: 'test' }, {}];
    for (const testCase of testCases) {
      const encoded = CBOR.encode(testCase);
      const decoded = CBOR.decode(encoded);
      expect(decoded).toEqual(testCase);
    }
  });

  test('encode/decode Date objects', () => {
    const date = new Date('2023-01-01T00:00:00.000Z');
    const encoded = CBOR.encode(date);
    const decoded = CBOR.decode(encoded);

    expect(decoded).toBeInstanceOf(Date);
    expect(decoded.toISOString()).toBe(date.toISOString());
  });

  test('encode/decode nested objects with dates', () => {
    const obj = {
      created: new Date('2023-01-01T00:00:00.000Z'),
      updated: new Date('2023-12-31T23:59:59.999Z'),
      data: {
        value: 42,
        tags: ['test', 'date'],
      },
    };

    const encoded = CBOR.encode(obj);
    const decoded = CBOR.decode(encoded);

    expect(decoded.created).toBeInstanceOf(Date);
    expect(decoded.updated).toBeInstanceOf(Date);
    expect(decoded.created.toISOString()).toBe(obj.created.toISOString());
    expect(decoded.updated.toISOString()).toBe(obj.updated.toISOString());
    expect(decoded.data).toEqual(obj.data);
  });

  test('encode/decode DataElement', () => {
    const data = { a: 1 };
    const dataElement = DataElement.fromData(data);

    const encoded = CBOR.encode(dataElement);
    const decoded = CBOR.decode(encoded);

    expect(decoded).toBeInstanceOf(DataElement);
    expect(new Uint8Array(decoded.buffer)).toEqual(
      new Uint8Array(dataElement.buffer),
    );
  });

  test('encode/decode Object with DataElement', () => {
    const data = {
      a: 1,
      dataElement: DataElement.fromData({ b: 2 }),
      date: new Date('2023-01-01T00:00:00.000Z'),
    };

    const encoded = CBOR.encode(data);
    const decoded = CBOR.decode(encoded);

    expect(decoded.dataElement).toBeInstanceOf(DataElement);
    expect(new Uint8Array(decoded.dataElement.buffer)).toEqual(
      new Uint8Array(data.dataElement.buffer),
    );
    expect(decoded.date).toBeInstanceOf(Date);
    expect(decoded.date.toISOString()).toBe(data.date.toISOString());
  });
});
