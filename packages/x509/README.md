# CBOR encoder/decoder for mdl

This package provides a [CBOR](https://datatracker.ietf.org/doc/html/rfc7049) encoder/decoder for the mdoc/mdl(ISO/IEC 18013-5).

## Installation

```bash
npm install @m-doc/x509
```

```bash
yarn install @m-doc/x509
```

```bash
pnpm install @m-doc/x509
```

## Usage

### Encode

```typescript
const textEncoder = new TextEncoder();
const textencode = (data: string) => textEncoder.encode(data);
const cborEncoder = new CBOREncoder(textencode);

const buffer = cborEncoder.encode('hi');
console.log(buffer);
```

### Decode

```typescript
const textDecoder = new TextDecoder();
const textdecode = (data: Uint8Array) => textDecoder.decode(data);
const cborDecoder = new CBORDecoder(textdecode);

const buffer = new Uint8Array([0x62, 0x68, 0x69]); // 'hi'
const data = cborDecoder.decode(new Uint8Array(buffer));
console.log(data);
```
