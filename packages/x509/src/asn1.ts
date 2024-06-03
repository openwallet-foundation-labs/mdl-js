export class ASN1Parser {
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
