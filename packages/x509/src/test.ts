class CertificateParser {
  private pemString: string;
  private certificate: any;

  constructor(pem: string) {
    this.pemString = pem;
    this.parseCertificate();
  }

  private parseCertificate() {
    // PEM 문자열에서 불필요한 부분 제거
    const trimmedPem = this.pemString
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\n/g, '');

    // Base64 디코딩
    const derBuffer = new Uint8Array(
      atob(trimmedPem)
        .split('')
        .map((c) => c.charCodeAt(0)),
    );

    //console.log(derBuffer);

    // ASN.1 파싱 로직 구현
    let offset = 0;
    const certificate: any = {};

    //console.log(0, derBuffer[0]); // 48 check

    // ASN.1 시퀀스 태그(0x30) 확인
    if (derBuffer[offset++] !== 0x30) {
      throw new Error('Invalid certificate format');
    }

    // 전체 길이 확인
    const totalLength = this.parseLength(derBuffer, offset);
    offset += totalLength.len;

    if (derBuffer[offset++] !== 0x30) {
      throw new Error('Invalid certificate format');
    }

    const tbsCertLength = this.parseLength(derBuffer, offset);
    offset += tbsCertLength.len;

    //console.log({ totalLength, tbsCertLength });

    //console.log(length, offset); // check
    // len: 575, offset: 4 (1+3)

    //console.log('version', derBuffer[offset], 0xa0);
    // 버전 확인

    certificate.version = this.parseVersion(derBuffer, offset);
    offset += certificate.version.len;

    /*
    console.log(
      'version',
      certificate.version.value,
      offset,
      derBuffer[offset],
    ); // check
    */

    certificate.serialNumber = this.parseSerialNumber(derBuffer, offset);
    offset += certificate.serialNumber.len;

    // console.log(Buffer.from(certificate.serialNumber.value), offset); // check

    certificate.signatureAlgorithm = this.parseSignatureAlgorithm(
      derBuffer,
      offset,
    );
    offset += certificate.signatureAlgorithm.len;
    console.log('signatureAlgorithm', certificate.signatureAlgorithm, offset);

    /*
    // 서명 알고리즘 추출
    certificate.signatureAlgorithm = this.parseSignatureAlgorithm(
      derBuffer,
      offset,
    );
    offset += certificate.signatureAlgorithm.len;
    console.log('signatureAlgorithm', certificate.signatureAlgorithm, offset);

    // 일련번호 추출
    certificate.serialNumber = this.parseSerialNumber(derBuffer, offset);
    offset += certificate.serialNumber.len;

    // 발급자 추출
    certificate.issuer = this.parseIssuer(derBuffer, offset);
    offset += certificate.issuer.len;

    // 유효 기간 추출
    certificate.validity = this.parseValidity(derBuffer, offset);
    offset += certificate.validity.len;

    // 주체 추출
    certificate.subject = this.parseSubject(derBuffer, offset);
    offset += certificate.subject.len;

    // 공개 키 추출
    certificate.publicKey = this.parsePublicKey(derBuffer, offset);
    offset += certificate.publicKey.len;
    */

    this.certificate = certificate;
    console.log(this.certificate);
  }

  private parseLength(
    buffer: Uint8Array,
    offset: number,
  ): { len: number; value: number } {
    const firstByte = buffer[offset++];
    if (firstByte & 0x80) {
      const lengthBytes = firstByte & 0x7f;
      let length = 0;
      for (let i = 0; i < lengthBytes; i++) {
        length = (length << 8) | buffer[offset++];
      }
      return { len: lengthBytes + 1, value: length };
    } else {
      return { len: 1, value: firstByte };
    }
  }

  private parseExplicit(
    buffer: Uint8Array,
    offset: number,
  ): { len: number; value: number } {
    if (buffer[offset++] !== 0xa0) {
      throw new Error('Invalid explicit tag');
    }

    const length = this.parseLength(buffer, offset);
    offset += length.len;

    const value = this.parseInteger(buffer, offset);
    offset += value.len;

    return { len: 1 + length.len + value.len, value: value.value };
  }

  private parseInteger(
    buffer: Uint8Array,
    offset: number,
  ): { len: number; value: number } {
    if (buffer[offset++] !== 0x02) {
      throw new Error('Invalid integer tag');
    }

    const length = this.parseLength(buffer, offset);
    offset += length.len;

    let value = 0;
    for (let i = 0; i < length.value; i++) {
      value = (value << 8) | buffer[offset + i];
    }

    return { len: 1 + length.len + length.value, value };
  }

  private parseVersion(
    buffer: Uint8Array,
    offset: number,
  ): { len: number; value: number } {
    if (buffer[offset] === 0xa0) {
      const explicitVersion = this.parseExplicit(buffer, offset);
      return { len: explicitVersion.len, value: explicitVersion.value };
    } else {
      return { len: 0, value: 0 }; // 기본 버전은 v1(0)
    }
  }

  private parseSerialNumber(
    buffer: Uint8Array,
    offset: number,
  ): { len: number; value: Uint8Array } {
    if (buffer[offset++] !== 0x02) {
      throw new Error('Invalid serial number tag');
    }

    const length = this.parseLength(buffer, offset);
    offset += length.len;

    const serialNumber = buffer.slice(offset, offset + length.value);

    return { len: 1 + length.len + length.value, value: serialNumber };
  }

  private parseSignatureAlgorithm(
    buffer: Uint8Array,
    offset: number,
  ): {
    len: number;
    value: { algorithm: string; parameters: null | Uint8Array };
  } {
    if (buffer[offset++] !== 0x30) {
      throw new Error('Invalid signature algorithm tag');
    }

    const length = this.parseLength(buffer, offset);
    offset += length.len;

    const endOffset = offset + length.value;

    if (buffer[offset++] !== 0x06) {
      throw new Error('Invalid OID tag');
    }

    const oidLength = this.parseLength(buffer, offset);
    offset += oidLength.len;

    const oid = Array.from(
      buffer.slice(offset, offset + oidLength.value),
      (byte) => byte.toString(16).padStart(2, '0'),
    ).join('.');
    offset += oidLength.value;

    let parameters: null | Uint8Array = null;
    if (offset < endOffset) {
      if (buffer[offset++] !== 0x05) {
        throw new Error('Invalid NULL tag');
      }
      parameters = null;
    }

    return { len: endOffset - offset, value: { algorithm: oid, parameters } };
  }

  private parseAny(
    buffer: Uint8Array,
    offset: number,
  ): { len: number; value: Uint8Array } {
    const tag = buffer[offset++];
    const length = this.parseLength(buffer, offset);
    offset += length.len;
    const value = buffer.slice(offset, offset + length.value);
    return { len: 1 + length.len + length.value, value };
  }

  private parseIssuer(
    buffer: Uint8Array,
    offset: number,
  ): { len: number; value: string } {
    const length = this.parseLength(buffer, offset);
    offset += length.len;
    const issuer = this.parseNameObject(buffer, offset, length.value);
    return { len: length.len + length.value, value: issuer };
  }

  private parseSubject(
    buffer: Uint8Array,
    offset: number,
  ): { len: number; value: string } {
    const length = this.parseLength(buffer, offset);
    offset += length.len;
    const subject = this.parseNameObject(buffer, offset, length.value);
    return { len: length.len + length.value, value: subject };
  }

  private parseValidity(
    buffer: Uint8Array,
    offset: number,
  ): { len: number; value: { notBefore: Date; notAfter: Date } } {
    const sequenceTag = buffer[offset++];
    if (sequenceTag !== 0x30) {
      throw new Error('Invalid validity format');
    }

    const length = this.parseLength(buffer, offset);
    offset += length.len;

    const notBefore = this.parseTime(buffer, offset);
    offset += notBefore.len;

    const notAfter = this.parseTime(buffer, offset);
    offset += notAfter.len;

    return {
      len: 1 + length.len + length.value,
      value: { notBefore: notBefore.value, notAfter: notAfter.value },
    };
  }

  private parseTime(
    buffer: Uint8Array,
    offset: number,
  ): { len: number; value: Date } {
    const tag = buffer[offset++];
    const length = this.parseLength(buffer, offset);
    offset += length.len;
    const timeStr = new TextDecoder().decode(
      buffer.slice(offset, offset + length.value),
    );
    console.log({ tag, timeStr });
    let time: Date;
    if (tag === 0x17) {
      time = this.parseUTCTime(timeStr);
    } else if (tag === 0x18) {
      time = this.parseGeneralizedTime(timeStr);
    } else {
      throw new Error('Invalid time format');
    }
    return { len: 1 + length.len + length.value, value: time };
  }

  private parseUTCTime(timeStr: string): Date {
    const year = Number(timeStr.slice(0, 2));
    const month = Number(timeStr.slice(2, 4)) - 1;
    const day = Number(timeStr.slice(4, 6));
    const hour = Number(timeStr.slice(6, 8));
    const minute = Number(timeStr.slice(8, 10));
    const second = Number(timeStr.slice(10, 12));
    const utcTime = Date.UTC(
      year >= 50 ? 1900 + year : 2000 + year,
      month,
      day,
      hour,
      minute,
      second,
    );
    return new Date(utcTime);
  }

  private parseGeneralizedTime(timeStr: string): Date {
    const year = Number(timeStr.slice(0, 4));
    const month = Number(timeStr.slice(4, 6)) - 1;
    const day = Number(timeStr.slice(6, 8));
    const hour = Number(timeStr.slice(8, 10));
    const minute = Number(timeStr.slice(10, 12));
    const second = Number(timeStr.slice(12, 14));
    const utcTime = Date.UTC(year, month, day, hour, minute, second);
    return new Date(utcTime);
  }

  private parseNameObject(
    buffer: Uint8Array,
    offset: number,
    length: number,
  ): string {
    const nameObject: { [key: string]: string } = {};
    const endOffset = offset + length;
    while (offset < endOffset) {
      const tag = buffer[offset++];
      const length = this.parseLength(buffer, offset);
      offset += length.len;
      const value = new TextDecoder().decode(
        buffer.slice(offset, offset + length.value),
      );
      offset += length.value;
      const oid = this.getOIDForTag(tag);
      nameObject[oid] = value;
    }
    return Object.entries(nameObject)
      .map(([key, value]) => `${key}=${value}`)
      .join(', ');
  }

  private getOIDForTag(tag: number): string {
    switch (tag) {
      case 0x55:
        return '2.5.4.6'; // countryName
      case 0x54:
        return '2.5.4.8'; // stateOrProvinceName
      case 0x4a:
        return '2.5.4.10'; // organizationName
      case 0x03:
        return '2.5.4.3'; // commonName
      default:
        return 'unknown';
    }
  }

  private parsePublicKey(
    buffer: Uint8Array,
    offset: number,
  ): { len: number; value: Uint8Array } {
    const length = this.parseLength(buffer, offset);
    offset += length.len;
    const publicKeyBuffer = buffer.slice(offset, offset + length.value);
    return { len: length.len + length.value, value: publicKeyBuffer };
  }

  getSubject(): string {
    return this.certificate.subject.value;
  }

  getIssuer(): string {
    return this.certificate.issuer.value;
  }

  getValidFrom(): Date {
    return this.certificate.validity.value.notBefore;
  }

  getValidTo(): Date {
    return this.certificate.validity.value.notAfter;
  }

  getSerialNumber(): Uint8Array {
    return this.certificate.serialNumber.value;
  }

  getPublicKey(): Uint8Array {
    return this.certificate.publicKey.value;
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

// 30 82023F 30 8201E5 A0 03 020102 02 14 5DDD2890E38CE5CCA517073658D2BB0F63BE02B0 30 0A 06 08 2A8648CE3D040302 30 51 31 0B 30 09 06 03 550406 13 02 5553 31 0E 30 0C 06 03 550408 0C 05 55532D4341 310F300D060355040A0C0643412D444D563121301F06035504030C1843616C69666F726E696120444D56204941434120526F6F74301E170D3233303330313137313733395A170D3333303130373137313733395A3051310B3009060355040613025553310E300C06035504080C0555532D4341310F300D060355040A0C0643412D444D563121301F06035504030C1843616C69666F726E696120444D56204941434120526F6F743059301306072A8648CE3D020106082A8648CE3D0301070342000460CCA07942C457606C6621AA40DE294BA17083C604CC236240AC0EF6550F602F60C82A4040725298B62C7BBD0C146E16C7EFA9A799B3854B1625089B6295F975A3819A308197301D0603551D0E04160414BB7D7567927A6FCF9F727BB80AF7372F9C0C503630120603551D130101FF040830060101FF020100300E0603551D0F0101FF040403020106301F0603551D12041830168114696163612D726F6F7440646D762E63612E676F7630310603551D1F042A30283026A024A022862068747470733A2F2F63726C2E646D762E63612E676F762F696163612F726F6F74300A06082A8648CE3D0403020348003045022009AE22B8C0453380308AFBEB48216FA05C0494208706FD7841371BA4DAE1DDED022100A582F0B15A33CA85B2F96E8ED6597FAE3BCC3F0105CEA489C8F5226C3FC2E8D2

/*
30 82 02 3F                                     ; SEQUENCE (575 bytes)
   30 82 01 E5                                  ; tbsCertificate SEQUENCE (485 bytes)
      A0 03                                     ; version EXPLICIT [0] (3 bytes)
         02 01 02                               ; INTEGER (2)
      02 14                                     ; serialNumber INTEGER (20 bytes)
         5D DD 28 90 E3 8C E5 CC A5 17 07 36 58 D2 BB 0F 63 BE 02 B0
      30 0D                                     ; signature SEQUENCE (13 bytes)
         06 09                                  ; OBJECT IDENTIFIER (9 bytes)
            2A 86 48 86 F7 0D 01 01 0B          ; 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
         05 00                                  ; NULL
      30 81 9B                                  ; issuer SEQUENCE (155 bytes)
         31 0B                                  ; SET (11 bytes)
            30 09                               ; SEQUENCE (9 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 04 06                      ; 2.5.4.6 (countryName)
               13 02 55 53                      ; PrintableString (2 bytes) "US"
         31 0E                                  ; SET (14 bytes)
            30 0C                               ; SEQUENCE (12 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 04 08                      ; 2.5.4.8 (stateOrProvinceName)
               0C 05 55 53 2D 43 41             ; UTF8String (5 bytes) "US-CA"
         31 0F                                  ; SET (15 bytes)
            30 0D                               ; SEQUENCE (13 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 04 0A                      ; 2.5.4.10 (organizationName)
               0C 06 43 41 2D 44 4D 56          ; UTF8String (6 bytes) "CA-DMV"
         31 21                                  ; SET (33 bytes)
            30 1F                               ; SEQUENCE (31 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 04 03                      ; 2.5.4.3 (commonName)
               0C 18 43 61 6C 69 66 6F 72 6E 69 61 20 44 4D 56 20 49 41 43 41 20 52 6F 6F 74 ; UTF8String (24 bytes) "California DMV IACA Root"
      30 1E                                     ; validity SEQUENCE (30 bytes)
         17 0D 32 33 30 33 30 31 31 37 31 37 33 39 5A ; UTCTime (13 bytes) "230301171739Z"
         17 0D 33 33 30 31 30 37 31 37 31 37 33 39 5A ; UTCTime (13 bytes) "330107171739Z"
      30 81 9B                                  ; subject SEQUENCE (155 bytes)
         31 0B                                  ; SET (11 bytes)
            30 09                               ; SEQUENCE (9 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 04 06                      ; 2.5.4.6 (countryName)
               13 02 55 53                      ; PrintableString (2 bytes) "US"
         31 0E                                  ; SET (14 bytes)
            30 0C                               ; SEQUENCE (12 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 04 08                      ; 2.5.4.8 (stateOrProvinceName)
               0C 05 55 53 2D 43 41             ; UTF8String (5 bytes) "US-CA"
         31 0F                                  ; SET (15 bytes)
            30 0D                               ; SEQUENCE (13 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 04 0A                      ; 2.5.4.10 (organizationName)
               0C 06 43 41 2D 44 4D 56          ; UTF8String (6 bytes) "CA-DMV"
         31 21                                  ; SET (33 bytes)
            30 1F                               ; SEQUENCE (31 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 04 03                      ; 2.5.4.3 (commonName)
               0C 18 43 61 6C 69 66 6F 72 6E 69 61 20 44 4D 56 20 49 41 43 41 20 52 6F 6F 74 ; UTF8String (24 bytes) "California DMV IACA Root"
      30 59                                     ; subjectPublicKeyInfo SEQUENCE (89 bytes)
         30 13                                  ; SEQUENCE (19 bytes)
            06 07                               ; OBJECT IDENTIFIER (7 bytes)
               2A 86 48 CE 3D 02 01             ; 1.2.840.10045.2.1 (ecPublicKey)
            06 08                               ; OBJECT IDENTIFIER (8 bytes)
               2A 86 48 CE 3D 03 01 07          ; 1.2.840.10045.3.1.7 (prime256v1)
         03 42                                  ; BIT STRING (66 bytes)
            00 04 60 CC A0 79 42 C4 57 60 6C 66 21 AA 40 DE 29 4B A1 70 83 C6 04 CC 23 62 40 AC 0E F6 55 0F 60 2F 60 C8 2A 40 40 72 52 98 B6 2C 7B BD 0C 14 6E 16 C7 EF A9 A7 99 B3 85 4B 16 25 08 9B 62 95 F9 75
      A3 81 9A                                  ; extensions [3] EXPLICIT (154 bytes)
         30 81 97                               ; SEQUENCE (151 bytes)
            30 1D                               ; SEQUENCE (29 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 1D 0E                      ; 2.5.29.14 (subjectKeyIdentifier)
               04 16                            ; OCTET STRING (22 bytes)
                  BB 7D 75 67 92 7A 6F CF 9F 72 7B B8 0A F7 37 2F 9C 0C 50 36
            30 12                               ; SEQUENCE (18 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 1D 13                      ; 2.5.29.19 (basicConstraints)
               01 01 FF                         ; BOOLEAN (1 byte) TRUE
               04 08                            ; OCTET STRING (8 bytes)
                  30 06 01 01 FF 02 01 00       ; SEQUENCE (6 bytes)
            30 0E                               ; SEQUENCE (14 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 1D 0F                      ; 2.5.29.15 (keyUsage)
               01 01 FF                         ; BOOLEAN (1 byte) TRUE
               04 04                            ; OCTET STRING (4 bytes)
                  03 02 01 06                   ; BIT STRING (2 bytes) 000001100000
            30 1F                               ; SEQUENCE (31 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 1D 11                      ; 2.5.29.17 (subjectAltName)
               04 18                            ; OCTET STRING (24 bytes)
                  30 16 81 14 69 61 63 61 2D 72 6F 6F 74 40 64 6D 76 2E 63 61 2E 67 6F 76 ; SEQUENCE (22 bytes)
            30 31                               ; SEQUENCE (49 bytes)
               06 03                            ; OBJECT IDENTIFIER (3 bytes)
                  55 1D 1F                      ; 2.5.29.31 (cRLDistributionPoints)
               04 2A                            ; OCTET STRING (42 bytes)
                  30 28                         ; SEQUENCE (40 bytes)
                     A0 26                      ; [0] (38 bytes)
                        A0 24                   ; [0] (36 bytes)
                           86 22               ; IA5String (34 bytes) "https://crl.dmv.ca.gov/iaca/root"
   30 0D                                        ; signatureAlgorithm SEQUENCE (13 bytes)
      06 09                                     ; OBJECT IDENTIFIER (9 bytes)
         2A 86 48 86 F7 0D 01 01 0B             ; 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
      05 00                                     ; NULL
   03 48                                        ; signatureValue BIT STRING (72 bytes)
      00 30 45 02 20 09 AE 22 B8 C0 45 33 80 30 8A FB EB 48 21 6F A0 5C 04 94 20 87 06 FD 78 41 37 1B A4 DA E1 DD ED 02 21 00 A5 82 F0 B1 5A 33 CA 85 B2 F9 6E 8E D6 59 7F AE 3B CC 3F 01 05 CE A4 89 C8 F5 22 6C 3F C2 E8 D2
*/
