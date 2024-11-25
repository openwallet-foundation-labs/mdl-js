export type OrPromise<T> = T | Promise<T>;
export type Hasher = (data: ArrayBuffer) => OrPromise<ArrayBuffer>;
export type RandomGenerator = () => OrPromise<Uint8Array>;

export enum MDocStatus {
  OK = 0,
  GeneralError = 10,
  CBORDecodingError = 11,
  CBORValidationError = 12,
}
