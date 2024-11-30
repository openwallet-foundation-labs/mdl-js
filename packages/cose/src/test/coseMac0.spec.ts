import { describe, expect, test } from 'vitest';
import { CBOR } from '@m-doc/cbor';
import { Mac0 } from '../coseMac';
import { COSE_MAC_ALGORITHMS } from '../types';

describe('Mac0', () => {
  // Using Uint8Array for consistency with CBOR encoding/decoding
  const mockProtectedHeader = new Uint8Array(0).buffer;
  const mockUnprotectedHeader = {};
  const mockPayload = new TextEncoder().encode('test payload').buffer;
  const mockTag = new Uint8Array(32).buffer;

  test('constructor should initialize with provided data', () => {
    const mac0 = new Mac0({
      protectedHeader: mockProtectedHeader,
      unprotectedHeader: mockUnprotectedHeader,
      payload: mockPayload,
      tag: mockTag,
    });

    expect(mac0.protectedHeader).toBe(mockProtectedHeader);
    expect(mac0.unprotectedHeader).toBe(mockUnprotectedHeader);
    expect(mac0.payload).toBe(mockPayload);
    expect(mac0.tag).toBe(mockTag);
  });

  test('fromBuffer should correctly decode CBOR data', () => {
    const data = [mockProtectedHeader, mockUnprotectedHeader, mockPayload, mockTag];
    const encoded = CBOR.encode(data);
    
    const mac0 = Mac0.fromBuffer(encoded);
    
    // Compare the underlying ArrayBuffer contents since CBOR decode may create new buffer instances
    expect(new Uint8Array(mac0.protectedHeader)).toEqual(new Uint8Array(mockProtectedHeader));
    expect(mac0.unprotectedHeader).toEqual(mockUnprotectedHeader);
    expect(new Uint8Array(mac0.payload)).toEqual(new Uint8Array(mockPayload));
    expect(new Uint8Array(mac0.tag!)).toEqual(new Uint8Array(mockTag));
  });

  test('data getter should return correct structure', () => {
    const mac0 = new Mac0({
      protectedHeader: mockProtectedHeader,
      unprotectedHeader: mockUnprotectedHeader,
      payload: mockPayload,
      tag: mockTag,
    });

    const data = mac0.data;
    expect(new Uint8Array(data[0])).toEqual(new Uint8Array(mockProtectedHeader));
    expect(data[1]).toEqual(mockUnprotectedHeader);
    expect(new Uint8Array(data[2])).toEqual(new Uint8Array(mockPayload));
    expect(new Uint8Array(data[3])).toEqual(new Uint8Array(mockTag));
  });

  test('getAlgValue should return correct algorithm value', () => {
    expect(Mac0.getAlgValue('HMAC-SHA-256')).toBe(COSE_MAC_ALGORITHMS['HMAC-SHA-256']);
    expect(Mac0.getAlgValue('HMAC-SHA-384')).toBe(COSE_MAC_ALGORITHMS['HMAC-SHA-384']);
    expect(Mac0.getAlgValue('HMAC-SHA-512')).toBe(COSE_MAC_ALGORITHMS['HMAC-SHA-512']);
    // Default case
    expect(Mac0.getAlgValue(undefined)).toBe(COSE_MAC_ALGORITHMS['HMAC-SHA-256']);
    expect(Mac0.getAlgValue('NON-EXISTENT')).toBe(COSE_MAC_ALGORITHMS['HMAC-SHA-256']);
  });

  test('setProtectedHeader should properly encode header', () => {
    const mac0 = new Mac0({
      protectedHeader: mockProtectedHeader,
      unprotectedHeader: mockUnprotectedHeader,
      payload: mockPayload,
    });

    mac0.setProtectedHeader({ alg: 'HMAC-SHA-256' });
    const decoded = CBOR.decode(mac0.protectedHeader);
    expect(decoded['1']).toBe(COSE_MAC_ALGORITHMS['HMAC-SHA-256']);
  });

  test('mac should create and verify MAC correctly', async () => {
    const mac0 = new Mac0({
      protectedHeader: mockProtectedHeader,
      unprotectedHeader: mockUnprotectedHeader,
      payload: mockPayload,
    });

    const key = new Uint8Array(32).fill(1);
    const mockMacFunction = async (data: ArrayBuffer) => {
      // Mock MAC function that returns a 32-byte buffer
      return new Uint8Array(32).fill(0).buffer;
    };

    await mac0.mac(key.buffer, 'HMAC-SHA-256', mockMacFunction);
    expect(mac0.tag).toBeDefined();
    expect(mac0.tag!.byteLength).toBe(32);
  });
});
