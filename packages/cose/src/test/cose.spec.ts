import { describe, expect, test } from 'vitest';
import { coseToJwk, jwkToCose } from '../index';

const jwkSample = {
  kty: 'EC',
  d: 'KLW1HN6uABbNBqkbAdQwySKMsKjU7MbOzyX4fjggWgY',
  use: 'sig',
  crv: 'P-256',
  x: 'TKb0u9N7eZNIEXQ04Z2O_2yB9-Uw1OonSerLqxNMmfA',
  y: 'GFdvH4e2NHQz40Bgs1jyXZkSbTSj-3SHo-NEVubSwGA',
  alg: 'ES256',
};

describe('COSE', () => {
  test('simple', () => {
    const cose = jwkToCose(jwkSample);
    expect(cose).toBeDefined();
  });

  test('convert again', () => {
    const cose = jwkToCose(jwkSample);
    const jwk = coseToJwk(cose);

    expect(jwk.d).toEqual(jwkSample.d);
    expect(jwk.x).toEqual(jwkSample.x);
    expect(jwk.y).toEqual(jwkSample.y);
    expect(jwk.kty).toEqual(jwkSample.kty);
    expect(jwk.crv).toEqual(jwkSample.crv);
  });
});
