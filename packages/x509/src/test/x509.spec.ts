import { describe, expect, test } from 'vitest';
import { X509Certificate } from '../index';

const textDecoder = new TextDecoder();
const textdecode = (data: ArrayBuffer) => textDecoder.decode(data);

const pem1 = `MIIBXjCCAQSgAwIBAgIGAY/YZ7BdMAoGCCqGSM49BAMCMDYxNDAyBgNVBAMMKzJJ
NjZKNi1lbGx4N2pIY3RnRVMyZEdXbGhoRGhzSXZ1X0dBU1B1Q0VGMDgwHhcNMjQw
NjAyMTAwMzQ1WhcNMjUwMzI5MTAwMzQ1WjA2MTQwMgYDVQQDDCsySTY2SjYtZWxs
eDdqSGN0Z0VTMmRHV2xoaERoc0l2dV9HQVNQdUNFRjA4MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEWn/dSPASseG60dh2H4Hsqy2zGC8lDQstyrXo2GsKmHiTbv/y
Se5TikdKulSRWGF4qERk+YUQN8LnJBC+rnN15DAKBggqhkjOPQQDAgNIADBFAiEA
3Y8VJnZJV6QwBZP+Q9Bq/76FJG+yqyS/kdsQgYhBfwACIEyctJoEVUAbLxw1uVhk
IKfehXmTBmqzb064GBeqJ++P`;

const pem2 = `-----BEGIN CERTIFICATE-----
MIICPzCCAeWgAwIBAgIUXd0okOOM5cylFwc2WNK7D2O+ArAwCgYIKoZIzj0EAwIw
UTELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVVTLUNBMQ8wDQYDVQQKDAZDQS1ETVYx
ITAfBgNVBAMMGENhbGlmb3JuaWEgRE1WIElBQ0EgUm9vdDAeFw0yMzAzMDExNzE3
MzlaFw0zMzAxMDcxNzE3MzlaMFExCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVVUy1D
QTEPMA0GA1UECgwGQ0EtRE1WMSEwHwYDVQQDDBhDYWxpZm9ybmlhIERNViBJQUNB
IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARgzKB5QsRXYGxmIapA3ilL
oXCDxgTMI2JArA72VQ9gL2DIKkBAclKYtix7vQwUbhbH76mnmbOFSxYlCJtilfl1
o4GaMIGXMB0GA1UdDgQWBBS7fXVnknpvz59ye7gK9zcvnAxQNjASBgNVHRMBAf8E
CDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAfBgNVHRIEGDAWgRRpYWNhLXJvb3RA
ZG12LmNhLmdvdjAxBgNVHR8EKjAoMCagJKAihiBodHRwczovL2NybC5kbXYuY2Eu
Z292L2lhY2Evcm9vdDAKBggqhkjOPQQDAgNIADBFAiAJriK4wEUzgDCK++tIIW+g
XASUIIcG/XhBNxuk2uHd7QIhAKWC8LFaM8qFsvlujtZZf647zD8BBc6kicj1Imw/
wujS
-----END CERTIFICATE-----`;

describe('X509Certificate Parser', () => {
  test('parses a simple X509 certificate', () => {
    const x509Certificate = new X509Certificate(pem1, textdecode);
    expect(x509Certificate.data).toStrictEqual({
      extensions: {},
      issuer: {
        data: {
          CN: '2I66J6-ellx7jHctgES2dGWlhhDhsIvu_GASPuCEF08',
        },
        simple: 'CN=2I66J6-ellx7jHctgES2dGWlhhDhsIvu_GASPuCEF08',
      },
      serialNumber: '018fd867b05d',
      signatureAlgorithm: 'ecdsa-with-SHA256',
      subject: {
        data: {
          CN: '2I66J6-ellx7jHctgES2dGWlhhDhsIvu_GASPuCEF08',
        },
        simple: 'CN=2I66J6-ellx7jHctgES2dGWlhhDhsIvu_GASPuCEF08',
      },
      subjectPublicKeyInfo: {
        algorithm: 'ecPublicKey',
        publicKey:
          '00045a7fdd48f012b1e1bad1d8761f81ecab2db3182f250d0b2dcab5e8d86b0a9878936efff249ee538a474aba5491586178a84464f9851037c2e72410beae7375e4',
      },
      validity: {
        notAfter: new Date('2025-03-29T10:03:45.000Z'),
        notBefore: new Date('2024-06-02T10:03:45.000Z'),
      },
      version: 3,
    });
  });

  test('parses a ca mdl X509 certificate', () => {
    const x509Certificate = new X509Certificate(pem2, textdecode);
    expect(x509Certificate.data).toStrictEqual({
      extensions: {
        basicConstraints: {
          isCA: true,
          pathLenConstraint: null,
        },
        cRLDistributionPoints: 'https://crl.dmv.ca.gov/iaca/root',
        issuerAltName: 'iaca-root@dmv.ca.gov',
        keyUsage: [
          'Digital Signature',
          'Non Repudiation',
          'Key Encipherment',
          'Data Encipherment',
          'Key Agreement',
          'Key Cert Sign',
          'CRL Sign',
          'Encipher Only',
        ],
        subjectKeyIdentifier: '0414bb7d7567927a6fcf9f727bb80af7372f9c0c5036',
      },
      issuer: {
        data: {
          C: 'US',
          CN: 'California DMV IACA Root',
          O: 'CA-DMV',
          ST: 'US-CA',
        },
        simple: 'C=US, ST=US-CA, O=CA-DMV, CN=California DMV IACA Root',
      },
      serialNumber: '5ddd2890e38ce5cca517073658d2bb0f63be02b0',
      signatureAlgorithm: 'ecdsa-with-SHA256',
      subject: {
        data: {
          C: 'US',
          CN: 'California DMV IACA Root',
          O: 'CA-DMV',
          ST: 'US-CA',
        },
        simple: 'C=US, ST=US-CA, O=CA-DMV, CN=California DMV IACA Root',
      },
      subjectPublicKeyInfo: {
        algorithm: 'ecPublicKey',
        publicKey:
          '000460cca07942c457606c6621aa40de294ba17083c604cc236240ac0ef6550f602f60c82a4040725298b62c7bbd0c146e16c7efa9a799b3854b1625089b6295f975',
      },
      validity: {
        notAfter: new Date('2033-01-07T17:17:39.000Z'),
        notBefore: new Date('2023-03-01T17:17:39.000Z'),
      },
      version: 3,
    });
  });
});
