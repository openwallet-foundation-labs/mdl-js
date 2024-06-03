import { ASN1, ASN1Parser } from './asn1';
import { oidMap, simpleOidMap } from './oid';
import { Base64 } from 'js-base64';

export class X509Certificate {
  private parsedData: ASN1;
  public data: { [key: string]: unknown } | null = null;

  constructor(pem: string) {
    const trimmedPem = pem
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\n/g, '');
    const binaryCert = Base64.toUint8Array(trimmedPem);
    const parser = new ASN1Parser(binaryCert.buffer);
    this.parsedData = parser.parse();
    this.parse();
  }

  private parse() {
    const version = this.getVersion();
    const serialNumber = this.getSerialNumber();
    const signatureAlgorithm = this.getSignatureAlgorithm();
    const issuer = this.getIssuer();
    const validity = this.getValidity();
    const subject = this.getSubject();
    const subjectPublicKeyInfo = this.getSubjectPublicKeyInfo();
    const extensions = this.getExtensions();

    this.data = {
      version,
      serialNumber,
      signatureAlgorithm,
      issuer,
      validity,
      subject,
      subjectPublicKeyInfo,
      extensions,
    };
  }

  public getVersion(): number {
    const tbsCertificate = (this.parsedData.value as ASN1[])[0];
    const versionElement = (tbsCertificate.value as ASN1[])[0];
    if (versionElement.tag === 0xa0) {
      // EXPLICIT [0]
      const version = (versionElement.value as ASN1[])[0];
      if (version.tag === 0x02) {
        // INTEGER
        return new DataView(version.value as ArrayBuffer).getUint8(0) + 1; // X.509 version is 1-based
      }
    }
    return 1; // Default version is v1 if version field is not present
  }

  public getSerialNumber(): string {
    const tbsCertificate = (this.parsedData.value as ASN1[])[0];
    const serialNumberElement = (tbsCertificate.value as ASN1[])[1];
    if (serialNumberElement.tag === 0x02) {
      // INTEGER
      return this.toHexString(serialNumberElement.value as ArrayBuffer);
    }
    return '';
  }

  private toHexString(buffer: ArrayBuffer): string {
    return Buffer.from(buffer).toString('hex');
  }

  public getSignatureAlgorithm(): string {
    const tbsCertificate = (this.parsedData.value as ASN1[])[0];
    const signatureAlgorithmElement = (tbsCertificate.value as ASN1[])[2];
    if (signatureAlgorithmElement.tag === 0x30) {
      // SEQUENCE
      const algorithmIdentifier = (
        signatureAlgorithmElement.value as ASN1[]
      )[0];
      if (algorithmIdentifier.tag === 0x06) {
        // OBJECT IDENTIFIER
        return this.oidToName(algorithmIdentifier.value as ArrayBuffer);
      }
    }
    return 'Unknown';
  }

  private oidToName(oid: ArrayBuffer): string {
    const oidHex = this.toHexString(oid);
    return oidMap[oidHex] || `Unknown OID: ${oidHex}`;
  }

  public getIssuer(): {
    simple: string;
    data: { [key: string]: string };
  } {
    const tbsCertificate = (this.parsedData.value as ASN1[])[0];
    const issuerElement = (tbsCertificate.value as ASN1[])[3];
    if (issuerElement.tag === 0x30) {
      // SEQUENCE
      return this.parseName(issuerElement);
    }
    return { simple: '', data: {} };
  }

  private parseName(nameElement: ASN1): {
    simple: string;
    data: { [key: string]: string };
  } {
    const rdnSequence = nameElement.value as ASN1[];
    const data: { [key: string]: string } = {};
    const simple = rdnSequence
      .map((rdnSet: ASN1) => {
        const rdn = (rdnSet.value as ASN1[])[0];
        const oid = this.oidToSimpleName(
          (rdn.value as ASN1[])[0].value as ArrayBuffer,
        );
        const value = this.bufferToString(
          (rdn.value as ASN1[])[1].value as ArrayBuffer,
        );
        data[oid] = value;
        return `${oid}=${value}`;
      })
      .join(', ');
    return { simple, data };
  }

  private oidToSimpleName(oid: ArrayBuffer): string {
    const oidHex = this.toHexString(oid);
    return simpleOidMap[oidHex] || `Unknown OID: ${oidHex}`;
  }

  private bufferToString(buffer: ArrayBuffer): string {
    return new TextDecoder().decode(buffer);
  }

  private parseTime(timeElement: ASN1): Date {
    const timeString = this.bufferToString(timeElement.value as ArrayBuffer);
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
    const tbsCertificate = (this.parsedData.value as ASN1[])[0];
    const validityElement = (tbsCertificate.value as ASN1[])[4];
    if (validityElement.tag === 0x30) {
      // SEQUENCE
      const notBeforeElement = (validityElement.value as ASN1[])[0];
      const notAfterElement = (validityElement.value as ASN1[])[1];
      return {
        notBefore: this.parseTime(notBeforeElement),
        notAfter: this.parseTime(notAfterElement),
      };
    }
    return { notBefore: new Date(0), notAfter: new Date(0) };
  }

  public getSubject(): {
    simple: string;
    data: { [key: string]: string };
  } {
    const tbsCertificate = (this.parsedData.value as ASN1[])[0];
    const subjectElement = (tbsCertificate.value as ASN1[])[5];
    if (subjectElement.tag === 0x30) {
      // SEQUENCE
      return this.parseName(subjectElement);
    }
    return { simple: '', data: {} };
  }

  public getSubjectPublicKeyInfo(): { algorithm: string; publicKey: string } {
    const tbsCertificate = (this.parsedData.value as ASN1[])[0];
    const subjectPublicKeyInfoElement = (tbsCertificate.value as ASN1[])[6];
    if (subjectPublicKeyInfoElement.tag === 0x30) {
      // SEQUENCE
      const algorithmIdentifierElement = (
        subjectPublicKeyInfoElement.value as ASN1[]
      )[0];
      const publicKeyElement = (subjectPublicKeyInfoElement.value as ASN1[])[1];
      const algorithm = this.parseAlgorithmIdentifier(
        algorithmIdentifierElement,
      );
      const publicKey = this.toHexString(publicKeyElement.value as ArrayBuffer);
      return { algorithm, publicKey };
    }
    return { algorithm: 'Unknown', publicKey: '' };
  }

  private parseAlgorithmIdentifier(element: ASN1): string {
    const oidElement = (element.value as ASN1[])[0];
    if (oidElement.tag === 0x06) {
      // OBJECT IDENTIFIER
      return this.oidToName(oidElement.value as ArrayBuffer);
    }
    return 'Unknown';
  }

  public getExtensions(): { [key: string]: unknown } {
    const tbsCertificate = (this.parsedData.value as ASN1[])[0];
    const extensionsElement = (tbsCertificate.value as ASN1[]).find(
      (element: ASN1) => element.tag === 0xa3,
    );
    if (extensionsElement) {
      const extensions = (extensionsElement.value as ASN1[])[0];
      if (extensions.tag === 0x30) {
        // SEQUENCE
        return this.parseExtensions(extensions);
      }
    }
    return {};
  }

  private parseExtensions(extensionsElement: ASN1): { [key: string]: unknown } {
    const extensions: { [key: string]: unknown } = {};
    (extensionsElement.value as ASN1[]).forEach((extensionElement: ASN1) => {
      const oidElement = (extensionElement.value as ASN1[])[0];
      const valueElement = (extensionElement.value as ASN1[])[1];
      const oid = this.oidToName(oidElement.value as ArrayBuffer);
      const value = this.parseExtensionValue(oid, valueElement.value);
      extensions[oid] = value;
    });
    return extensions;
  }

  private parseExtensionValue(
    oid: string,
    value: ArrayBuffer | ASN1[],
  ): unknown {
    switch (oid) {
      case 'subjectKeyIdentifier':
        return this.toHexString(value as ArrayBuffer);
      case 'basicConstraints':
        return this.parseBasicConstraints(value as ArrayBuffer);
      case 'keyUsage':
        return this.parseKeyUsage(value as ArrayBuffer);
      case 'issuerAltName':
        return this.parseGeneralNames(value as ASN1[]); // simple string return
      case 'cRLDistributionPoints':
        return this.parseCRLDistributionPoints(value as ASN1[]); // simple string return
      default:
        return this.toHexString(value as ArrayBuffer); // basic HexString return
    }
  }

  private parseGeneralNames(valueElement: ASN1[]) {
    const generalNames = valueElement[0].value as ArrayBuffer;
    return this.bufferToString(generalNames);
  }

  private parseCRLDistributionPoints(valueElement: ASN1[]) {
    const distributionPoints = valueElement[0].value as ASN1[];
    return distributionPoints
      .map((dp: ASN1) => {
        const dpName = (dp.value as ASN1[])[0];
        if (dpName && dpName.value && (dpName.value as ASN1[])[0]) {
          return this.bufferToString(
            (dpName.value as ASN1[])[0].value as ArrayBuffer,
          );
        }
        return '';
      })
      .join(', ');
  }

  private parseBasicConstraints(value: ArrayBuffer) {
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
