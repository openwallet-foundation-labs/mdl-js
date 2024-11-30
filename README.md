# mDL Implementation in JavasScript (TypeScript)

This is the reference implmentation of [ISO 18013-5](https://www.iso.org/standard/69084.html) defines mDL (mobile Driver Licenses) specification written in TypeScript. It aims to provide a production-ready, robust and secure way to handle.

## Supported Platforms

- Node.js
- Browser
- React Native

## Concepts

- Platform agnostic: Our library is platform agnostic and does not depend on any specific platform.
- Bring your own crypto: Our library is platform agnostic and does not depend on any cryptographic library. It is up to the user to provide the cryptographic library they want to use.
- Modular design: Our library is modular and can be used in different scenarios. It is up to the user to decide which features they want to use.
- TypeScript: Our library is written in TypeScript and provides type definitions for the API.
- Easy to use: Our library is easy to use and provides a simple API for handling mDL data.

## Features

- [x] Issue mDL Document
- [x] Present mDL Document
- [x] Verify mDL Document
- [x] Decode mDL Document
- [x] Decode X509 Certificate

## Installation

```bash
npm install @m-doc/mdl
```

```bash
yarn install @m-doc/mdl
```

```bash
pnpm install @m-doc/mdl
```

## Version

We keep all the versions of our packages in sync.

## Usage

```Typescript
async function test() {
  const { publicKey, privateKey } = await ES256.generateKeyPair();
  const signer = await ES256.getSigner(privateKey);
  const verifier = await ES256.getVerifier(publicKey);

  const isDoc = new mdl.IssuerSignedDocument({
    docType: DOC_TYPE,
  });

  await isDoc.addNamespace(
    DEFAULT_NAMESPACE,
    {
      name: 'Lukas',
      id: '1234',
    },
    generateRandomBytesSync,
  );

  await isDoc.signIssuerAuth(
    { alg: 'ES256', signer },
    { digestAlgorithm: 'SHA-256', hasher: hash },
    {
      signed: new Date(),
      validFrom: new Date(),
      validUntil: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
    },
    {
      deviceKey: coseFromJwk(jwkSample),
    },
    undefined,
    {
      kid: '1234',
    },
  );

  const ret = await isDoc.validateIssuerAuth(verifier);
  console.log(ret);

  await isDoc.addDeviceSignature(
    {
      deviceEngagementBytes: new ArrayBuffer(3),
      eReaderKeyBytes: new ArrayBuffer(5),
      handover: ['handover'],
    },
    { alg: 'ES256', signer },
  );

  const devRet = await isDoc.verifyDeviceSignature(verifier);
  console.log(devRet);

  const a = new mdl.MDoc({
    documents: [isDoc],
  });
  const encodedMdl = a.encode();

  const result = arrayBufferToHexString(encodedMdl);
  console.log(result);

  const decodedMdl = mdl.MDoc.fromBuffer(encodedMdl);
  console.log(decodedMdl);
}
```

To see the details, please refer to the [examples](https://github.com/openwallet-foundation-labs/mdl-js/tree/master/examples/mdl) folder.

## License

Apache-2.0

## Contributing

New features and bug fixes are welcome! Please open an issue or pull request if you find any bugs or have any suggestions.
