import { describe, expect, test } from 'vitest';
import { areEqual, CBOREncoder } from '../index';
import { decode, encode } from 'cbor';

const textEncoder = new TextEncoder();
const textencode = (data: string) => textEncoder.encode(data);

describe('CBOR encode', () => {
  test('Simple Encode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode('hi');
    expect(areEqual(buffer, new Uint8Array([0x62, 0x68, 0x69]))).toBe(true);
  });

  test('Encode with cbor', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer1 = cborEncoder.encode('hi');
    const buffer2 = encode('hi');
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode number', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(42);
    expect(areEqual(buffer, new Uint8Array([0x18, 0x2a]))).toBe(true);
  });

  test('Encode number with cbor', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer1 = cborEncoder.encode(42);
    const buffer2 = encode(42);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode negative number', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(-42);
    expect(areEqual(buffer, new Uint8Array([0x38, 0x29]))).toBe(true);
  });

  test('Encode negative number with cbor', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer1 = cborEncoder.encode(-42);
    const buffer2 = encode(-42);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode boolean (true)', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(true);
    expect(areEqual(buffer, new Uint8Array([0xf5]))).toBe(true);
  });

  test('Encode boolean(true) with cbor', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer1 = cborEncoder.encode(true);
    const buffer2 = encode(true);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode boolean (false)', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(false);
    expect(areEqual(buffer, new Uint8Array([0xf4]))).toBe(true);
  });

  test('Encode boolean(false) with cbor', () => {
    const buffer1 = encode(false);
    const cborEncoder = new CBOREncoder(textencode);
    const buffer2 = cborEncoder.encode(false);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode null', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(null);
    expect(areEqual(buffer, new Uint8Array([0xf6]))).toBe(true);
  });

  test('Encode null with cbor', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer1 = cborEncoder.encode(null);
    const buffer2 = encode(null);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode undefined', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(undefined);
    expect(areEqual(buffer, new Uint8Array([0xf7]))).toBe(true);
  });

  test('Encode undefined with cbor', () => {
    const buffer1 = encode(undefined);
    const cborEncoder = new CBOREncoder(textencode);
    const buffer2 = cborEncoder.encode(undefined);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode float', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(0.5);
    expect(
      areEqual(
        buffer,
        new Uint8Array([0xfb, 0x3f, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
      ),
    ).toBe(true);
  });

  test('Encode float with cbor', () => {
    const buffer1 = encode(0.23);
    const cborEncoder = new CBOREncoder(textencode);
    const buffer2 = cborEncoder.encode(0.23);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode float(negative)', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(-0.5);
    expect(
      areEqual(
        buffer,
        new Uint8Array([0xfb, 0xbf, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
      ),
    ).toBe(true);
  });

  test('Encode float(negative) with cbor', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(-0.5);
    const data = decode(Buffer.from(buffer));
    expect(data).toBe(-0.5);
  });

  test('Encode array', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode([1, 2, 3]);
    expect(areEqual(buffer, new Uint8Array([0x83, 0x01, 0x02, 0x03]))).toBe(
      true,
    );
  });

  test('Encode array with cbor', () => {
    const buffer1 = encode([1, 2, 3]);
    const cborEncoder = new CBOREncoder(textencode);
    const buffer2 = cborEncoder.encode([1, 2, 3]);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode object', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode({ a: 1, b: 2 });
    expect(
      areEqual(
        buffer,
        new Uint8Array([0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02]),
      ),
    ).toBe(true);
  });

  test('Encode object with cbor', () => {
    const buffer1 = encode({ a: 1, b: 2 });
    const cborEncoder = new CBOREncoder(textencode);
    const buffer2 = cborEncoder.encode({ a: 1, b: 2 });
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('buffer', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(new Uint8Array([1, 2, 3, 4]));
    const buffer1 = decode(buffer);
    console.log(buffer1);
    expect(
      areEqual(buffer, new Uint8Array([0x44, 0x01, 0x02, 0x03, 0x04])),
    ).toBe(true);
    expect(areEqual(buffer1, new Uint8Array([1, 2, 3, 4]))).toBe(true);
  });

  test('nested json', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const data = {
      name: 'John',
      scores: [95, 87, 91],
      metadata: {
        timestamp: 1234567890,
        type: 'exam',
      },
    };
    const buffer = cborEncoder.encode(data);
    const decoded = decode(buffer);
    expect(decoded).toEqual(data);
  });
});
