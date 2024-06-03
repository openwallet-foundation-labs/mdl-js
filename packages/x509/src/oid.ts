export const oidMap: { [key: string]: string } = {
  '2a864886f70d010101': 'rsaEncryption',
  '2a864886f70d01010b': 'sha256WithRSAEncryption',
  '2a864886f70d01010c': 'sha384WithRSAEncryption',
  '2a864886f70d01010d': 'sha512WithRSAEncryption',
  '2a8648ce3d0201': 'ecPublicKey',
  '2a8648ce3d040301': 'ecdsa-with-SHA256',
  '2a8648ce3d040302': 'ecdsa-with-SHA384',
  '2a8648ce3d040303': 'ecdsa-with-SHA512',
  '608648016503040201': 'sha256',
  '608648016503040202': 'sha384',
  '608648016503040203': 'sha512',
  '2a864886f70d010701': 'data',
  '2a864886f70d010702': 'signedData',
  '2a864886f70d010901': 'emailAddress',
  '550403': 'commonName',
  '550404': 'surname',
  '550405': 'serialNumber',
  '550406': 'countryName',
  '550407': 'localityName',
  '550408': 'stateOrProvinceName',
  '550409': 'streetAddress',
  '55040a': 'organizationName',
  '55040b': 'organizationalUnitName',
  '55040c': 'title',
  '55040d': 'description',
  '55042a': 'givenName',
  '551d0e': 'subjectKeyIdentifier',
  '551d0f': 'keyUsage',
  '551d11': 'subjectAltName',
  '551d13': 'basicConstraints',
  '551d20': 'certificatePolicies',
  '551d23': 'authorityKeyIdentifier',
  '551d12': 'issuerAltName',
  '551d1f': 'cRLDistributionPoints',
};

export const simpleOidMap: { [key: string]: string } = {
  '550406': 'C', // Country Name
  '550408': 'ST', // State or Province Name
  '55040a': 'O', // Organization Name
  '55040b': 'OU', // Organizational Unit Name
  '550403': 'CN', // Common Name
  '550409': 'L', // Locality Name
};
