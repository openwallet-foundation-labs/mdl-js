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
async function example() {
  // Generate ES256 key pair for signing and verification
  const { publicKey, privateKey } = await ES256.generateKeyPair();
  const signer = await ES256.getSigner(privateKey);
  const verifier = await ES256.getVerifier(publicKey);

  // Create a new Issuer Signed Document with specified document type
  const issuedDocument = new mdl.IssuerSignedDocument({
    docType: DOC_TYPE,
  });

  // Add user data to the default namespace
  // generateRandomBytesSync is used for generating random values for security
  await issuedDocument.addNamespace(
    DEFAULT_NAMESPACE,
    {
      name: 'John Smith',
      id: 'DL123456789',
    },
    generateRandomBytesSync,
  );

  // Sign the document with issuer authentication
  // This includes validity period, device key, and signature metadata
  await issuedDocument.signIssuerAuth(
    { alg: 'ES256', signer }, // Signing algorithm and signer
    { digestAlgorithm: 'SHA-256', hasher: hash }, // Hashing configuration
    {
      signed: new Date(), // Current timestamp
      validFrom: new Date(), // Start of validity period
      validUntil: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30), // End of validity (30 days)
    },
    {
      deviceKey: coseFromJwk(jwkSample), // Device key in COSE format
    },
    undefined,
    {
      kid: '1234', // Key identifier
    },
  );

  // Validate the issuer authentication signature
  const verificationResult = await issuedDocument.validateIssuerAuth(verifier);
  console.log(verificationResult);

  // Add device signature with engagement data
  // This represents the device-specific authentication
  await issuedDocument.addDeviceSignature(
    {
      deviceEngagementBytes: new ArrayBuffer(3),
      eReaderKeyBytes: new ArrayBuffer(5),
      handover: ['handover'],
    },
    { alg: 'ES256', signer },
  );

  // Verify the device signature
  const deviceResponseVerificationResult =
    await issuedDocument.verifyDeviceSignature(verifier);
  console.log(deviceResponseVerificationResult);

  // Create a Mobile Document (MDoc) containing the signed document
  // and encode it to binary format
  const mobileDocument = new mdl.MDoc({
    documents: [issuedDocument],
  });
  const encodedMobileDocument = mobileDocument.encode();

  // Convert the encoded document to hex string for display/transport
  const hexEncodedDocument = arrayBufferToHexString(encodedMobileDocument);
  console.log(hexEncodedDocument);

  // Demonstrate decoding: convert the encoded document back to MDoc
  const decodedMobileDocument = mdl.MDoc.fromBuffer(encodedMobileDocument);
  console.log(decodedMobileDocument);
}
```

To see the details, please refer to the [examples](https://github.com/openwallet-foundation-labs/mdl-js/tree/master/examples/mdl) folder.

## License

Apache-2.0

## Contributing

New features and bug fixes are welcome! Please open an issue or pull request if you find any bugs or have any suggestions.
