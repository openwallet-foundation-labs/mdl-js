export enum MDocStatus {
  OK = 0,
  GeneralError = 10,
  CBORDecodingError = 11,
  CBORValidationError = 12,
}

export class MDoc {
  public readonly version = '1.0';
  public readonly documents: any[] = [];
  public readonly status: MDocStatus = MDocStatus.OK;
}
