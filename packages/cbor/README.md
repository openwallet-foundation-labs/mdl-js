# CBOR encoder/decoder for mdl

This package provides a [CBOR](https://datatracker.ietf.org/doc/html/rfc7049) encoder/decoder for the mdoc/mdl(ISO/IEC 18013-5).

## Supported Platforms

- Node.js
- Browser
- React Native

## Installation

```bash
npm install @m-doc/cbor
```

```bash
yarn install @m-doc/cbor
```

```bash
pnpm install @m-doc/cbor
```

## Usage

### Encode

```typescript
import { CBOR } from '@m-doc/cbor';
const encodedData = CBOR.encode('hello');
console.log(encodedData);
```

### Decode

```typescript
import { CBOR } from '@m-doc/cbor';
const decodedData = CBOR.decode(encodedData);
console.log(decodedData);
```

## License

Apache-2.0

## More Information

See the original Repo: https://github.com/openwallet-foundation-labs/mdl-js
