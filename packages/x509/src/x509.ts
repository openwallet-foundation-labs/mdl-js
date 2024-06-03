import { oidMap } from './oid';

export class X509Certificate {
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
        const oid = this.oidToSimpleName(rdn.value[0].value);
        const value = this.bufferToString(rdn.value[1].value);
        return `${oid}=${value}`;
      })
      .join(', ');
  }

  private oidToSimpleName(oid: ArrayBuffer): string {
    const oidHex = this.toHexString(oid);
    const simpleOidMap: { [key: string]: string } = {
      '550406': 'C', // Country Name
      '550408': 'ST', // State or Province Name
      '55040a': 'O', // Organization Name
      '55040b': 'OU', // Organizational Unit Name
      '550403': 'CN', // Common Name
      '550409': 'L', // Locality Name
    };
    return simpleOidMap[oidHex] || `Unknown OID: ${oidHex}`;
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
