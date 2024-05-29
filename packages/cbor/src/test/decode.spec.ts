import { describe, expect, test } from 'vitest';
import { CBORDecoder } from '../index';
import { encode } from 'cbor';

const textDecoder = new TextDecoder();
const textdecode = (data: Uint8Array) => textDecoder.decode(data);

describe('CBOR decode', () => {
  test('simple decode', () => {
    const buffer = new Uint8Array([0x62, 0x68, 0x69]);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(buffer);
    expect(data).toBe('hi');
  });

  test('string decode', () => {
    const buffer = encode('hi');
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe('hi');
  });

  test('number decode', () => {
    const buffer = encode(123);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(123);
  });

  test('negative number decode', () => {
    const buffer = encode(-123);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(-123);
  });

  test('0 decode', () => {
    const buffer = encode(0);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(0);
  });

  test('float decode', () => {
    const buffer = encode(1.23);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(1.23);
  });

  test('negative float decode', () => {
    const buffer = encode(-1.23);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(-1.23);
  });

  test('float16 decode', () => {
    const buffer = new Uint8Array([0xf9, 0x3c, 0x00]);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(1.0);
  });

  test('float32 decode', () => {
    const buffer = new Uint8Array([0xfa, 0x3f, 0x9d, 0x70, 0xa4]);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBeCloseTo(1.23);
  });

  test('float64 decode', () => {
    const buffer = new Uint8Array([
      0xfb, 0x3f, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(0.5);
  });

  test('null decode', () => {
    const buffer = encode(null);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(null);
  });

  test('undefined decode', () => {
    const buffer = encode(undefined);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(undefined);
  });

  test('boolean decode', () => {
    const buffer = encode(true);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(true);
  });

  test('boolean decode (false)', () => {
    const buffer = encode(false);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(false);
  });

  test('array decode', () => {
    const buffer = encode([1, 2, 3]);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toEqual([1, 2, 3]);
  });

  test('nested array decode', () => {
    const buffer = encode([1, [2, 3]]);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toEqual([1, [2, 3]]);
  });

  test('object decode', () => {
    const buffer = encode({ key: 'value' });
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toEqual({ key: 'value' });
  });

  test('nested object decode', () => {
    const buffer = encode({ key: { nested: 'value' } });
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toEqual({ key: { nested: 'value' } });
  });
});
