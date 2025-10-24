# AICredential Registry

A tamper-proof, decentralized registry for AI certifications and credentials on the Stacks blockchain. Organizations can issue verifiable certificates that users can cryptographically prove for job applications and grants.

## Features

- Authorized issuer management
- Immutable credential issuance
- Cryptographic verification of credentials
- Expiry date support
- Credential revocation capability

## Smart Contract Functions

### Public Functions

- `authorize-issuer` - Contract owner authorizes credential issuers
- `revoke-issuer` - Contract owner revokes issuer authorization
- `issue-credential` - Authorized issuers create verifiable credentials
- `revoke-credential` - Issuers can revoke their own credentials

### Read-Only Functions

- `get-credential` - Retrieve credential details by ID
- `is-authorized-issuer` - Check if principal is authorized issuer
- `get-holder-credentials` - List all credentials for a holder
- `get-issuer-credentials` - List all credentials from an issuer
- `verify-credential` - Cryptographically verify credential validity

## Usage

Educational institutions and certification bodies become authorized issuers. They issue tamper-proof credentials to learners. Recipients can prove their credentials to employers or grant programs through cryptographic verification.