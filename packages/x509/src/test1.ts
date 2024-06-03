import { X509Certificate } from 'crypto';

class CertificateParser {
  private cert: X509Certificate;

  constructor(pem: string) {
    this.cert = new X509Certificate(Buffer.from(pem));
  }

  getSubject(): string {
    return this.cert.subject;
  }

  getIssuer(): string {
    return this.cert.issuer;
  }

  getValidFrom() {
    return this.cert.validFrom;
  }

  getValidTo() {
    return this.cert.validTo;
  }

  getSerialNumber(): string {
    return this.cert.serialNumber;
  }

  getFingerprint(): string {
    return this.cert.fingerprint;
  }

  getPublicKey(): string {
    return this.cert.publicKey
      .export({ format: 'pem', type: 'spki' })
      .toString();
  }

  getPublicKeyUint8Array(): Uint8Array {
    return this.cert.publicKey.export({ format: 'der', type: 'spki' });
  }

  toString(): string {
    return this.cert.toString();
  }

  getPublicKeyHex(): string {
    const publicKeyDer = this.cert.publicKey.export({
      format: 'der',
      type: 'spki',
    });
    // SPKI 구조에서 공개 키 부분만 추출
    const publicKeyInfo = this.parsePublicKeyInfo(publicKeyDer.buffer);
    // Convert public key to hex string
    return Buffer.from(publicKeyInfo).toString('hex');
  }

  private parsePublicKeyInfo(derBuffer: ArrayBuffer): ArrayBuffer {
    // DER 형식의 SPKI 구조를 파싱하여 공개 키 부분만 추출하는 로직
    const view = new DataView(derBuffer);
    let offset = 0;

    // 읽기 유틸리티 함수들
    const readLength = () => {
      let length = view.getUint8(offset++);
      if (length & 0x80) {
        const numberOfBytes = length & 0x7f;
        length = 0;
        for (let i = 0; i < numberOfBytes; i++) {
          length = (length << 8) | view.getUint8(offset++);
        }
      }
      return length;
    };

    const readTag = () => view.getUint8(offset++);

    // SEQUENCE
    if (readTag() !== 0x30) throw new Error('Invalid SPKI format');
    readLength(); // Skip length

    // SEQUENCE (AlgorithmIdentifier)
    if (readTag() !== 0x30) throw new Error('Invalid SPKI format');
    const algIdLength = readLength();
    offset += algIdLength; // Skip AlgorithmIdentifier

    // BIT STRING
    if (readTag() !== 0x03) throw new Error('Invalid SPKI format');
    const bitStringLength = readLength();
    if (view.getUint8(offset++) !== 0x00)
      throw new Error('Invalid SPKI format'); // Skip unused bits byte

    // BIT STRING value (the public key)
    return derBuffer.slice(offset, offset + bitStringLength - 1);
  }
}

// 사용 예시
const pem = `
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`;

const parser = new CertificateParser(pem);

console.log('Subject:', parser.getSubject());
console.log('Issuer:', parser.getIssuer());
console.log('Valid From:', parser.getValidFrom());
console.log('Valid To:', parser.getValidTo());
console.log('Serial Number:', parser.getSerialNumber());
console.log('Fingerprint:', parser.getFingerprint());
console.log('Public Key:', parser.getPublicKey());

// 공개 키를 Uint8Array 형식으로 반환하는 메서드 호출
const publicKeyUint8Array = parser.getPublicKeyUint8Array();
// to hex string
const publicKeyHexString = Buffer.from(publicKeyUint8Array).toString('hex');
console.log('Public Key (hex):', publicKeyHexString);

// 공개 키를 hex string 형식으로 반환하는 메서드 호출
const publicKeyHex = parser.getPublicKeyHex();
console.log('Public Key (hex, direct):', publicKeyHex);
