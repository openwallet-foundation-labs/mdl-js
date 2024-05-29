import { describe, expect, test } from 'vitest';
import { CBORDecoder } from '../index';
import { decode, encode } from 'cbor';

const textDecoder = new TextDecoder();
const textdecode = (data: Uint8Array) => textDecoder.decode(data);

describe('CBOR decode', () => {
  test('simple decode', () => {
    const buffer = new Uint8Array([0x62, 0x68, 0x69]);
    const cborDecoder = new CBORDecoder(textdecode);
    const data = cborDecoder.decode(buffer);
    expect(data).toBe('hi');
  });
});
