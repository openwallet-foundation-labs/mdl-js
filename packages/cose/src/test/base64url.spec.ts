import { describe, expect, test } from 'vitest';
import {
  base64urlDecode,
  base64urlEncode,
  uint8ArrayToBase64Url,
  base64urlToUint8Array,
} from '../index';

describe('Base64url', () => {
  const raw = 'abcdefghijklmnopqrstuvwxyz';
  const encoded = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo';
  test('Encode', () => {
    expect(base64urlEncode(raw)).toStrictEqual(encoded);
  });
  test('Decode', () => {
    expect(base64urlDecode(encoded)).toStrictEqual(raw);
  });
  test('Encode and decode', () => {
    const str = 'hello world';
    expect(base64urlDecode(base64urlEncode(str))).toStrictEqual(str);
  });
  test('Uint8Array', () => {
    const str = 'hello world';
    const uint8 = new TextEncoder().encode(str);
    expect(uint8ArrayToBase64Url(uint8)).toStrictEqual(base64urlEncode(str));
  });

  test('Uint8Array to base64url and back', () => {
    const str = 'hello world';
    const uint8 = new TextEncoder().encode(str);
    const base64url = uint8ArrayToBase64Url(uint8);
    const uint8back = base64urlToUint8Array(base64url);
    expect(new TextDecoder().decode(uint8back)).toStrictEqual(str);
  });
});
