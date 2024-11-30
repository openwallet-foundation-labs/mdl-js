# Decoder for mdl

This package provides a decoder function for the mdoc/mdl(ISO/IEC 18013-5).

## Supported Platforms

- Node.js
- Browser
- React Native

## Installation

```bash
npm install @m-doc/decode
```

```bash
yarn install @m-doc/decode
```

```bash
pnpm install @m-doc/decode
```

## Usage

```typescript
import { decodeMdl } from '@m-doc/decode';

const rawMdl = decodeMdl(buffer); // buffer is an ArrayBuffer
console.log(rawMdl);
```

To see the details, please refer to the [examples](https://github.com/openwallet-foundation-labs/mdl-js/tree/master/examples/mdl) folder.

## License

Apache-2.0

## More Information

See the original Repo: https://github.com/openwallet-foundation-labs/mdl-js
