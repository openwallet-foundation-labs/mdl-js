export type OrPromise<T> = T | Promise<T>;
export type protectedHeader = {
  alg?: string;
  kid?: string;
  [key: string]: unknown;
};
