import { describe, expect, test } from 'vitest';
import { concat, areEqual } from '../index';

describe('CBOR utils', () => {
  test('concat', () => {
    const buffer1 = new Uint8Array([0x62, 0x68]);
    const buffer2 = new Uint8Array([0x69]);
    const buffer = concat(buffer1, buffer2);
    expect(areEqual(buffer, new Uint8Array([0x62, 0x68, 0x69]))).toBe(true);
  });

  test('areEqual', () => {
    const buffer1 = new Uint8Array([0x62, 0x68, 0x69]);
    const buffer2 = new Uint8Array([0x62, 0x68, 0x69]);
    expect(areEqual(buffer1, buffer2)).toBe(true);
  });

  test('areEqual with same buffer', () => {
    const buffer = new Uint8Array([0x62, 0x68, 0x69]);
    expect(areEqual(buffer, buffer)).toBe(true);
  });

  test('areEqual with different length', () => {
    const buffer1 = new Uint8Array([0x62, 0x68, 0x69]);
    const buffer2 = new Uint8Array([0x62, 0x68]);
    expect(areEqual(buffer1, buffer2)).toBe(false);
  });

  test('areEqual with different value', () => {
    const buffer1 = new Uint8Array([0x62, 0x68, 0x69]);
    const buffer2 = new Uint8Array([0x62, 0x68, 0x68]);
    expect(areEqual(buffer1, buffer2)).toBe(false);
  });
});
