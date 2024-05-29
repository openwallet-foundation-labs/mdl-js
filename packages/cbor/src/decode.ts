export type TextDecoder = (data: Uint8Array) => string;

export class CBORDecoder {
  private textDecoder: TextDecoder;
  constructor(textDecoder: TextDecoder) {
    this.textDecoder = textDecoder;
  }

  public decode<T extends unknown = unknown>(data: Uint8Array): T {
    const decoder = new Decoder(data, this.textDecoder);
    return decoder.decode() as T;
  }
}

class Decoder {
  private dataView: DataView;
  private offset: number;
  private textDecoder: TextDecoder;

  constructor(data: Uint8Array, textDecoder: TextDecoder) {
    this.dataView = new DataView(data.buffer);
    this.offset = 0;
    this.textDecoder = textDecoder;
  }

  public decode(): unknown {
    const type = this.dataView.getUint8(this.offset);
    this.offset++;

    if (type >= 0x00 && type <= 0x17) return type;
    if (type >= 0x20 && type <= 0x37) return -(type - 0x20 + 1);
    if (type === 0x18) return this.decodeUint8();
    if (type === 0x19) return this.decodeUint16();
    if (type === 0x1a) return this.decodeUint32();
    if (type === 0x1b) return this.decodeUint64();
    if (type === 0x38) return -this.decodeUint8() - 1;
    if (type === 0x39) return -this.decodeUint16() - 1;
    if (type === 0x3a) return -this.decodeUint32() - 1;
    if (type === 0x3b) return -this.decodeBigInt() - 1n;
    if (type === 0xf9) return this.decodeFloat16();
    if (type === 0xfa) return this.decodeFloat32();
    if (type === 0xfb) return this.decodeFloat64();
    if (type === 0xf4) return false;
    if (type === 0xf5) return true;
    if (type === 0xf6) return null;
    if (type === 0xf7) return undefined;
    if (type >= 0x60 && type <= 0x77) return this.decodeString(type - 0x60);
    if (type === 0x78) return this.decodeString(this.decodeUint8());
    if (type === 0x79) return this.decodeString(this.decodeUint16());
    if (type === 0x7a) return this.decodeString(this.decodeUint32());
    if (type === 0x7b) return this.decodeString(Number(this.decodeBigInt())); // Warn: bigint to number: precision loss
    if (type >= 0x80 && type <= 0x97) return this.decodeArray(type - 0x80);
    if (type === 0x98) return this.decodeArray(this.decodeUint8());
    if (type === 0x99) return this.decodeArray(this.decodeUint16());
    if (type === 0x9a) return this.decodeArray(this.decodeUint32());
    if (type === 0x9b) return this.decodeArray(this.decodeBigInt());
    if (type >= 0xa0 && type <= 0xb7) return this.decodeObject(type - 0xa0);
    if (type === 0xb8) return this.decodeObject(this.decodeUint8());
    if (type === 0xb9) return this.decodeObject(this.decodeUint16());
    if (type === 0xba) return this.decodeObject(this.decodeUint32());
    if (type === 0xbb) return this.decodeObject(this.decodeBigInt());

    throw new Error('Invalid CBOR data');
  }

  private decodeUint8() {
    const value = this.dataView.getUint8(this.offset);
    this.offset++;
    return value;
  }

  private decodeUint16() {
    const value = this.dataView.getUint16(this.offset);
    this.offset += 2;
    return value;
  }

  private decodeUint32() {
    const value = this.dataView.getUint32(this.offset);
    this.offset += 4;
    return value;
  }

  private decodeUint64() {
    const high = this.dataView.getUint32(this.offset);
    const low = this.dataView.getUint32(this.offset + 4);
    this.offset += 8;
    return high * 0x100000000 + low;
  }

  private decodeBigInt() {
    const high = this.dataView.getBigUint64(this.offset);
    const low = this.dataView.getBigUint64(this.offset + 8);
    this.offset += 16;
    return (high << 64n) + low;
  }

  private decodeFloat16() {
    const value = this.dataView.getUint16(this.offset);
    this.offset += 2;
    const sign = (value & 0x8000) !== 0 ? -1 : 1;
    const exponent = (value & 0x7c00) >> 10;
    const fraction = value & 0x03ff;

    if (exponent === 0) {
      return sign * Math.pow(2, -24) * fraction;
    } else if (exponent === 0x1f) {
      return fraction === 0 ? sign * Infinity : NaN;
    } else {
      return sign * Math.pow(2, exponent - 25) * (1024 + fraction);
    }
  }

  private decodeFloat32() {
    const value = this.dataView.getFloat32(this.offset);
    this.offset += 4;
    return value;
  }

  private decodeFloat64() {
    const value = this.dataView.getFloat64(this.offset);
    this.offset += 8;
    return value;
  }

  private decodeString(length: number) {
    const bytes = new Uint8Array(this.dataView.buffer, this.offset, length);
    this.offset += length;
    return this.textDecoder(bytes);
  }

  private decodeArray(length: number | bigint) {
    const array: Array<unknown> = [];
    for (let i = 0; i < length; i++) {
      array.push(this.decode());
    }
    return array;
  }

  private decodeObject(length: number | bigint) {
    const object: Record<string, unknown> = {};
    for (let i = 0; i < length; i++) {
      const key = this.decode() as string;
      object[key] = this.decode();
    }
    return object;
  }
}
