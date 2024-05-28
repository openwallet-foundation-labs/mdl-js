import { describe, expect, test } from 'vitest';
import { encodeCBOR, areEqual } from '../index';
import { encode } from 'cbor';

describe('Base64url', () => {
  test('Encode', () => {
    const buffer = encodeCBOR('hi');
    expect(areEqual(buffer, new Uint8Array([0x62, 0x68, 0x69]))).toBe(true);
  });

  test('Encode with cbor', () => {
    const buffer1 = encode('hi');
    const buffer2 = encodeCBOR('hi');
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode number', () => {
    const buffer = encodeCBOR(42);
    expect(areEqual(buffer, new Uint8Array([0x18, 0x2a]))).toBe(true);
  });

  test('Encode number with cbor', () => {
    const buffer1 = encode(42);
    const buffer2 = encodeCBOR(42);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode negative number', () => {
    const buffer = encodeCBOR(-42);
    expect(areEqual(buffer, new Uint8Array([0x38, 0x29]))).toBe(true);
  });

  test('Encode negative number with cbor', () => {
    const buffer1 = encode(-42);
    const buffer2 = encodeCBOR(-42);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode boolean (true)', () => {
    const buffer = encodeCBOR(true);
    expect(areEqual(buffer, new Uint8Array([0xf5]))).toBe(true);
  });

  test('Encode boolean(true) with cbor', () => {
    const buffer1 = encode(true);
    const buffer2 = encodeCBOR(true);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode boolean (false)', () => {
    const buffer = encodeCBOR(false);
    expect(areEqual(buffer, new Uint8Array([0xf4]))).toBe(true);
  });

  test('Encode boolean(false) with cbor', () => {
    const buffer1 = encode(false);
    const buffer2 = encodeCBOR(false);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode null', () => {
    const buffer = encodeCBOR(null);
    expect(areEqual(buffer, new Uint8Array([0xf6]))).toBe(true);
  });

  test('Encode null with cbor', () => {
    const buffer1 = encode(null);
    const buffer2 = encodeCBOR(null);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode undefined', () => {
    const buffer = encodeCBOR(undefined);
    expect(areEqual(buffer, new Uint8Array([0xf7]))).toBe(true);
  });

  test('Encode undefined with cbor', () => {
    const buffer1 = encode(undefined);
    const buffer2 = encodeCBOR(undefined);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode float', () => {
    const buffer = encodeCBOR(0.5);
    console.log(Buffer.from(buffer));
    expect(
      areEqual(
        buffer,
        new Uint8Array([0xfb, 0x3f, 0xe0, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00]),
      ),
    ).toBe(true);
  });

  test('Encode float with cbor', () => {
    const buffer1 = encode(0.34);
    const buffer2 = encodeCBOR(0.34);
    //console.log(buffer1, Buffer.from(buffer2));
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode float(negative)', () => {
    const buffer = encodeCBOR(-0.5);
    expect(
      areEqual(
        buffer,
        new Uint8Array([0xfb, 0xbf, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
      ),
    ).toBe(true);
  });

  test('Encode float(negative) with cbor', () => {
    const buffer1 = encode(-0.5);
    const buffer2 = encodeCBOR(-0.5);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode array', () => {
    const buffer = encodeCBOR([1, 2, 3]);
    expect(areEqual(buffer, new Uint8Array([0x83, 0x01, 0x02, 0x03]))).toBe(
      true,
    );
  });

  test('Encode array with cbor', () => {
    const buffer1 = encode([1, 2, 3]);
    const buffer2 = encodeCBOR([1, 2, 3]);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('Encode object', () => {
    const buffer = encodeCBOR({ a: 1, b: 2 });
    expect(
      areEqual(
        buffer,
        new Uint8Array([0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02]),
      ),
    ).toBe(true);
  });

  test('Encode object with cbor', () => {
    const buffer1 = encode({ a: 1, b: 2 });
    const buffer2 = encodeCBOR({ a: 1, b: 2 });
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });
});
