import { ASN1Parser } from '../index';
import { describe, expect, test } from 'vitest';

// Helper function to create ArrayBuffer from hex string
function hexStringToArrayBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(
    hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
  );
  return bytes.buffer;
}

describe('ASN1Parser', () => {
  test('parses a simple ASN.1 primitive integer', () => {
    const testCase = hexStringToArrayBuffer('020101'); // INTEGER 1
    const parser = new ASN1Parser(testCase);
    const result = parser.parse();

    expect(result).toEqual({
      tag: 0x02,
      length: 1,
      value: new Uint8Array([0x01]).buffer,
    });
  });

  test('parses a simple ASN.1 primitive octet string', () => {
    const testCase = hexStringToArrayBuffer('0403616263'); // OCTET STRING 'abc'
    const parser = new ASN1Parser(testCase);
    const result = parser.parse();

    expect(result).toEqual({
      tag: 0x04,
      length: 3,
      value: new Uint8Array([0x61, 0x62, 0x63]).buffer,
    });
  });

  test('parses an ASN.1 sequence containing two integers', () => {
    const testCase = hexStringToArrayBuffer('3006020101020102'); // SEQUENCE { INTEGER 1, INTEGER 2 }
    const parser = new ASN1Parser(testCase);
    const result = parser.parse();

    expect(result).toEqual({
      tag: 0x30,
      length: 6,
      value: [
        {
          tag: 0x02,
          length: 1,
          value: new Uint8Array([0x01]).buffer,
        },
        {
          tag: 0x02,
          length: 1,
          value: new Uint8Array([0x02]).buffer,
        },
      ],
    });
  });

  test('parses a nested ASN.1 sequence', () => {
    const testCase = hexStringToArrayBuffer('30083006020101020102'); // SEQUENCE { SEQUENCE { INTEGER 1, INTEGER 2 } }
    const parser = new ASN1Parser(testCase);
    const result = parser.parse();

    expect(result).toEqual({
      tag: 0x30,
      length: 8,
      value: [
        {
          tag: 0x30,
          length: 6,
          value: [
            {
              tag: 0x02,
              length: 1,
              value: new Uint8Array([0x01]).buffer,
            },
            {
              tag: 0x02,
              length: 1,
              value: new Uint8Array([0x02]).buffer,
            },
          ],
        },
      ],
    });
  });

  test('parses a sequence containing an object which is a sequence', () => {
    const testCase = hexStringToArrayBuffer('300E3003020101300702020101020102'); // SEQUENCE { INTEGER 1, SEQUENCE { INTEGER 1, INTEGER 2 } }
    const parser = new ASN1Parser(testCase);
    const result = parser.parse();

    expect(result).toEqual({
      tag: 0x30,
      length: 14,
      value: [
        {
          tag: 0x30,
          length: 3,
          value: [
            {
              tag: 0x02,
              length: 1,
              value: new Uint8Array([0x01]).buffer,
            },
          ],
        },
        {
          tag: 0x30,
          length: 7,
          value: [
            {
              tag: 0x02,
              length: 2,
              value: new Uint8Array([0x01]).buffer,
            },
            {
              tag: 0x02,
              length: 1,
              value: new Uint8Array([0x02]).buffer,
            },
          ],
        },
      ],
    });
  });
});
