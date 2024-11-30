import { CBOR } from '@m-doc/cbor';
import { RawMdocData } from './types';

export function decodeMdl(buffer: ArrayBuffer) {
  const data = CBOR.decode<RawMdocData>(buffer);
  return data;
}
