import { describe, expect, test } from 'vitest';
import { concat, compareArrayBuffer } from '../index';

describe('COSE', () => {
  test('concat', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5, 6]);
    const c = concat(a, b);
    expect(c).toBeDefined();
    expect(c.length).toBe(a.length + b.length);
  });

  test('compare', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5, 6]);
    const c = new Uint8Array([1, 2, 3]);
    expect(compareArrayBuffer(a, c)).toBe(true);
    expect(compareArrayBuffer(a, b)).toBe(false);
  });
});
