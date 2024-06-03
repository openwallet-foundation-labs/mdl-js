const oidMap: { [key: string]: string } = {
  '2a864886f70d010101': 'rsaEncryption',
  '2a864886f70d01010b': 'sha256WithRSAEncryption',
  '2a864886f70d01010c': 'sha384WithRSAEncryption',
  '2a864886f70d01010d': 'sha512WithRSAEncryption',
  '2a8648ce3d0201': 'ecPublicKey',
  '2a8648ce3d040301': 'ecdsa-with-SHA256',
  '2a8648ce3d040302': 'ecdsa-with-SHA384',
  '2a8648ce3d040303': 'ecdsa-with-SHA512',
  '608648016503040201': 'sha256',
  '608648016503040202': 'sha384',
  '608648016503040203': 'sha512',
  '2a864886f70d010701': 'data',
  '2a864886f70d010702': 'signedData',
  '2a864886f70d010901': 'emailAddress',
  '550403': 'commonName',
  '550404': 'surname',
  '550405': 'serialNumber',
  '550406': 'countryName',
  '550407': 'localityName',
  '550408': 'stateOrProvinceName',
  '550409': 'streetAddress',
  '55040a': 'organizationName',
  '55040b': 'organizationalUnitName',
  '55040c': 'title',
  '55040d': 'description',
  '55042a': 'givenName',
  '551d0e': 'subjectKeyIdentifier',
  '551d0f': 'keyUsage',
  '551d11': 'subjectAltName',
  '551d13': 'basicConstraints',
  '551d20': 'certificatePolicies',
  '551d23': 'authorityKeyIdentifier',
  '551d12': 'issuerAltName',
  '551d1f': 'cRLDistributionPoints',
};

class ASN1Parser {
  private buffer: ArrayBuffer;
  private view: DataView;
  private offset: number;

  constructor(buffer: ArrayBuffer) {
    this.buffer = buffer;
    this.view = new DataView(this.buffer);
    this.offset = 0;
  }

  private parseTag(): number {
    return this.view.getUint8(this.offset++);
  }

  private parseLength(): number {
    let length = this.view.getUint8(this.offset++);
    if (length & 0x80) {
      const numberOfBytes = length & 0x7f;
      length = 0;
      for (let i = 0; i < numberOfBytes; i++) {
        length = (length << 8) | this.view.getUint8(this.offset++);
      }
    }
    return length;
  }

  private parseValue(tag: number, length: number): any {
    if ((tag & 0x20) === 0x20) {
      // Constructed types
      const endOffset = this.offset + length;
      const value: any[] = [];
      while (this.offset < endOffset) {
        value.push(this.parse());
      }
      return value;
    } else {
      // Primitive types
      const value = this.buffer.slice(this.offset, this.offset + length);
      this.offset += length;

      // Check if the value is a sequence
      if (tag === 0x04 && new DataView(value).getUint8(0) === 0x30) {
        const sequenceParser = new ASN1Parser(value);
        return sequenceParser.parse().value;
      }

      return value;
    }
  }

  public parse(): any {
    const tag = this.parseTag();
    const length = this.parseLength();
    const value = this.parseValue(tag, length);

    return {
      tag,
      length,
      value,
    };
  }

  public printParsedData(parsedData: any, indent: string = ''): void {
    const { tag, length, value } = parsedData;
    console.log(
      `${indent}Tag: ${tag.toString(16).padStart(2, '0').toUpperCase()}`,
    );
    console.log(`${indent}Length: ${length}`);
    if (Array.isArray(value)) {
      console.log(`${indent}Value: [`);
      value.forEach((item: any) => this.printParsedData(item, indent + '  '));
      console.log(`${indent}]`);
    } else {
      console.log(`${indent}Value: ${this.formatValue(value)}`);
    }
  }

  private formatValue(value: any): string {
    if (value instanceof ArrayBuffer) {
      return Array.from(new Uint8Array(value))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join(' ');
    } else if (Array.isArray(value)) {
      return JSON.stringify(value);
    } else {
      return String(value);
    }
  }
}

class X509Certificate {
  private parsedData: any;

  constructor(parsedData: any) {
    this.parsedData = parsedData;
  }

  public getVersion(): number {
    const tbsCertificate = this.parsedData.value[0];
    const versionElement = tbsCertificate.value[0];
    if (versionElement.tag === 0xa0) {
      // EXPLICIT [0]
      const version = versionElement.value[0];
      if (version.tag === 0x02) {
        // INTEGER
        return new DataView(version.value).getUint8(0) + 1; // X.509 version is 1-based
      }
    }
    return 1; // Default version is v1 if version field is not present
  }

  public getSerialNumber(): string {
    const tbsCertificate = this.parsedData.value[0];
    const serialNumberElement = tbsCertificate.value[1];
    if (serialNumberElement.tag === 0x02) {
      // INTEGER
      return this.toHexString(serialNumberElement.value);
    }
    return '';
  }

  private toHexString(buffer: ArrayBuffer): string {
    return Buffer.from(buffer).toString('hex');
  }

  public getSignatureAlgorithm(): string {
    const tbsCertificate = this.parsedData.value[0];
    const signatureAlgorithmElement = tbsCertificate.value[2];
    if (signatureAlgorithmElement.tag === 0x30) {
      // SEQUENCE
      const algorithmIdentifier = signatureAlgorithmElement.value[0];
      if (algorithmIdentifier.tag === 0x06) {
        // OBJECT IDENTIFIER
        return this.oidToAlgorithm(algorithmIdentifier.value);
      }
    }
    return 'Unknown';
  }

  private oidToAlgorithm(oid: ArrayBuffer): string {
    const oidHex = this.toHexString(oid);
    return oidMap[oidHex] || `Unknown OID: ${oidHex}`;
  }

  public getIssuer(): string {
    const tbsCertificate = this.parsedData.value[0];
    const issuerElement = tbsCertificate.value[3];
    if (issuerElement.tag === 0x30) {
      // SEQUENCE
      return this.parseName(issuerElement);
    }
    return '';
  }

  private parseName(nameElement: any): string {
    const rdnSequence = nameElement.value;
    return rdnSequence
      .map((rdnSet: any) => {
        const rdn = rdnSet.value[0];
        const oid = this.oidToName(rdn.value[0].value);
        const value = this.bufferToString(rdn.value[1].value);
        return `${oid}=${value}`;
      })
      .join(', ');
  }

  private oidToName(oid: ArrayBuffer): string {
    const oidHex = this.toHexString(oid);
    const oidMap: { [key: string]: string } = {
      '550406': 'C', // Country Name
      '550408': 'ST', // State or Province Name
      '55040a': 'O', // Organization Name
      '55040b': 'OU', // Organizational Unit Name
      '550403': 'CN', // Common Name
      '550409': 'L', // Locality Name
    };
    return oidMap[oidHex] || `Unknown OID: ${oidHex}`;
  }

  private bufferToString(buffer: ArrayBuffer): string {
    return new TextDecoder().decode(buffer);
  }

  private parseTime(timeElement: any): Date {
    const timeString = this.bufferToString(timeElement.value);
    // UTCTime format is YYMMDDHHMMSSZ
    const year = parseInt(timeString.slice(0, 2), 10) + 2000; // 2000 year base
    const month = parseInt(timeString.slice(2, 4), 10) - 1; // month is 0 started
    const day = parseInt(timeString.slice(4, 6), 10);
    const hours = parseInt(timeString.slice(6, 8), 10);
    const minutes = parseInt(timeString.slice(8, 10), 10);
    const seconds = parseInt(timeString.slice(10, 12), 10);
    return new Date(Date.UTC(year, month, day, hours, minutes, seconds));
  }

  public getValidity(): { notBefore: Date; notAfter: Date } {
    const tbsCertificate = this.parsedData.value[0];
    const validityElement = tbsCertificate.value[4];
    if (validityElement.tag === 0x30) {
      // SEQUENCE
      const notBeforeElement = validityElement.value[0];
      const notAfterElement = validityElement.value[1];
      return {
        notBefore: this.parseTime(notBeforeElement),
        notAfter: this.parseTime(notAfterElement),
      };
    }
    return { notBefore: new Date(0), notAfter: new Date(0) };
  }

  public getSubject(): string {
    const tbsCertificate = this.parsedData.value[0];
    const subjectElement = tbsCertificate.value[5];
    if (subjectElement.tag === 0x30) {
      // SEQUENCE
      return this.parseName(subjectElement);
    }
    return '';
  }

  public getSubjectPublicKeyInfo(): { algorithm: string; publicKey: string } {
    const tbsCertificate = this.parsedData.value[0];
    const subjectPublicKeyInfoElement = tbsCertificate.value[6];
    if (subjectPublicKeyInfoElement.tag === 0x30) {
      // SEQUENCE
      const algorithmIdentifierElement = subjectPublicKeyInfoElement.value[0];
      const publicKeyElement = subjectPublicKeyInfoElement.value[1];
      const algorithm = this.parseAlgorithmIdentifier(
        algorithmIdentifierElement,
      );
      const publicKey = this.toHexString(publicKeyElement.value);
      return { algorithm, publicKey };
    }
    return { algorithm: 'Unknown', publicKey: '' };
  }

  private parseAlgorithmIdentifier(element: any): string {
    const oidElement = element.value[0];
    if (oidElement.tag === 0x06) {
      // OBJECT IDENTIFIER
      return this.oidToAlgorithm(oidElement.value);
    }
    return 'Unknown';
  }

  public getExtensions(): { [key: string]: any } {
    const tbsCertificate = this.parsedData.value[0];
    const extensionsElement = tbsCertificate.value.find(
      (element: any) => element.tag === 0xa3,
    );
    if (extensionsElement) {
      const extensions = extensionsElement.value[0];
      if (extensions.tag === 0x30) {
        // SEQUENCE
        return this.parseExtensions(extensions);
      }
    }
    return {};
  }

  private parseExtensions(extensionsElement: any): { [key: string]: any } {
    const extensions: { [key: string]: any } = {};
    extensionsElement.value.forEach((extensionElement: any) => {
      const oidElement = extensionElement.value[0];
      const valueElement = extensionElement.value[1];
      const oid = this.oidToAlgorithm(oidElement.value);
      const value = this.parseExtensionValue(oid, valueElement.value);
      extensions[oid] = value;
    });
    return extensions;
  }

  private parseExtensionValue(oid: string, value: ArrayBuffer): any {
    switch (oid) {
      case 'subjectKeyIdentifier':
        return this.toHexString(value);
      case 'basicConstraints':
        return this.parseBasicConstraints(value);
      case 'keyUsage':
        return this.parseKeyUsage(value);
      case 'issuerAltName':
        return this.parseGeneralNames(value); // simple string return
      case 'cRLDistributionPoints':
        return this.parseCRLDistributionPoints(value); // simple string return
      default:
        return this.toHexString(value); // basic HexString return
    }
  }

  private parseGeneralNames(valueElement: any): any {
    const generalNames = valueElement[0].value;
    return this.bufferToString(generalNames);
  }

  private parseCRLDistributionPoints(valueElement: any): any {
    const distributionPoints = valueElement[0].value;
    return distributionPoints
      .map((dp: any) => {
        const dpName = dp.value[0];
        if (dpName && dpName.value && dpName.value[0]) {
          return this.bufferToString(dpName.value[0].value);
        }
        return '';
      })
      .join(', ');
  }

  private parseBasicConstraints(value: ArrayBuffer): any {
    const view = new DataView(value);
    const isCA = view.getUint8(0) !== 0;
    let pathLenConstraint: number | null = null;
    if (view.byteLength > 1) {
      pathLenConstraint = view.getUint8(1);
    }
    return { isCA, pathLenConstraint };
  }

  private parseKeyUsage(value: ArrayBuffer): string[] {
    const view = new DataView(value);
    const keyUsageBits = view.getUint8(0);
    const usage: string[] = [];
    if (keyUsageBits & 0x80) usage.push('Digital Signature');
    if (keyUsageBits & 0x40) usage.push('Non Repudiation');
    if (keyUsageBits & 0x20) usage.push('Key Encipherment');
    if (keyUsageBits & 0x10) usage.push('Data Encipherment');
    if (keyUsageBits & 0x08) usage.push('Key Agreement');
    if (keyUsageBits & 0x04) usage.push('Key Cert Sign');
    if (keyUsageBits & 0x02) usage.push('CRL Sign');
    if (keyUsageBits & 0x01) usage.push('Encipher Only');
    return usage;
  }
}

// 사용 예제
const pem = `MIIBXjCCAQSgAwIBAgIGAY/YZ7BdMAoGCCqGSM49BAMCMDYxNDAyBgNVBAMMKzJJ
NjZKNi1lbGx4N2pIY3RnRVMyZEdXbGhoRGhzSXZ1X0dBU1B1Q0VGMDgwHhcNMjQw
NjAyMTAwMzQ1WhcNMjUwMzI5MTAwMzQ1WjA2MTQwMgYDVQQDDCsySTY2SjYtZWxs
eDdqSGN0Z0VTMmRHV2xoaERoc0l2dV9HQVNQdUNFRjA4MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEWn/dSPASseG60dh2H4Hsqy2zGC8lDQstyrXo2GsKmHiTbv/y
Se5TikdKulSRWGF4qERk+YUQN8LnJBC+rnN15DAKBggqhkjOPQQDAgNIADBFAiEA
3Y8VJnZJV6QwBZP+Q9Bq/76FJG+yqyS/kdsQgYhBfwACIEyctJoEVUAbLxw1uVhk
IKfehXmTBmqzb064GBeqJ++P`;

const binaryCert = Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)).buffer;

const parser = new ASN1Parser(binaryCert);
const parsedCert = parser.parse();
parser.printParsedData(parsedCert);
const cert = new X509Certificate(parsedCert);
console.log(`Version: ${cert.getVersion()}`); // 예상 출력: Version: 3
console.log(`Serial Number: ${cert.getSerialNumber()}`); // 예상 출력: Serial Number: 5ddd2890e38ce5cca517073658d2bb0f63be02b0
console.log(`Signature Algorithm: ${cert.getSignatureAlgorithm()}`); // 예상 출력: Signature Algorithm: ecdsa-with-SHA256
console.log(`Issuer: ${cert.getIssuer()}`); // 예상 출력: Issuer: C=US, ST=US-CA, O=CA-DMV, CN=California DMV IACA Root
const validity = cert.getValidity();
console.log(
  `Validity: Not Before: ${validity.notBefore}, Not After: ${validity.notAfter}`,
); // 예상 출력: 유효기간 정보
console.log(`Subject: ${cert.getSubject()}`); // 예상 출력: Subject: C=US, ST=US-CA, O=CA-DMV, CN=California DMV IACA Root
const subjectPublicKeyInfo = cert.getSubjectPublicKeyInfo();
console.log(
  `Subject Public Key Info: Algorithm: ${subjectPublicKeyInfo.algorithm}, Public Key: ${subjectPublicKeyInfo.publicKey}`,
); // 예상 출력: 공개 키 정보
const extensions = cert.getExtensions();
console.log('Extensions:', extensions); // 예상 출력: 확장 필드 정보
