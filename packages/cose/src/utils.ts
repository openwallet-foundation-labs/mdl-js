export function concat(...buffers: Uint8Array[]): Uint8Array {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf = new Uint8Array(size);
  let i = 0;
  buffers.forEach((buffer) => {
    buf.set(buffer, i);
    i += buffer.length;
  });
  return buf;
}

export function constantTimeArrayBufferCompare(
  a: ArrayBuffer,
  b: ArrayBuffer,
): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  const aView = new Uint8Array(a);
  const bView = new Uint8Array(b);
  let result = 0;

  for (let i = 0; i < a.byteLength; i++) {
    result |= aView[i] ^ bView[i];
  }

  return result === 0;
}
