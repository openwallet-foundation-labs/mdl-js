import { describe, expect, test } from 'vitest';
import { CBOREncoder, CBORDecoder } from '../index';

const textEncoder = new TextEncoder();
const textencode = (data: string) => textEncoder.encode(data);

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
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode('hi');
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe('hi');
  });

  test('number decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(123);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(123);
  });

  test('negative number decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(-123);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(-123);
  });

  test('0 decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(0);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(0);
  });

  test('float decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(1.23);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(1.23);
  });

  test('negative float decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(-1.23);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(-1.23);
  });

  test('null decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(null);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(null);
  });

  test('undefined decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(undefined);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(undefined);
  });

  test('boolean decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(true);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(true);
  });

  test('boolean decode (false)', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode(false);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toBe(false);
  });

  test('array decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode([1, 2, 3]);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toEqual([1, 2, 3]);
  });

  test('nested array decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode([1, [2, 3]]);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toEqual([1, [2, 3]]);
  });

  test('object decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode({ key: 'value' });
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toEqual({ key: 'value' });
  });

  test('nested object decode', () => {
    const cborEncoder = new CBOREncoder(textencode);
    const buffer = cborEncoder.encode({ key: { nested: 'value' } });
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(new Uint8Array(buffer));
    expect(data).toEqual({ key: { nested: 'value' } });
  });
});
