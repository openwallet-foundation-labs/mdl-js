// Import required modules for MDL (Mobile Driving License) implementation
import * as mdl from '@m-doc/mdl';
import { DOC_TYPE, DEFAULT_NAMESPACE } from '@m-doc/types';
import {
  arrayBufferToHexString,
  ES256,
  generateRandomBytesSync,
  hash,
  jwkSample,
} from './crypto';
import { coseFromJwk } from '@m-doc/cose';

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

// Execute the test function
example();
