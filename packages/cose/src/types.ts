export type OrPromise<T> = T | Promise<T>;
export type protectedHeader = {
  alg?: string;
  [key: string]: unknown;
};
