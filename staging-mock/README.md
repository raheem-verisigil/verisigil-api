# VeriSigil isolated staging mock

This directory is a synthetic, read-only test service. It is intentionally not the VeriSigil production API and contains no production code, credentials, customer records, authority issuance, authorization, revocation, or execution functionality.

## Routes

- `GET /health`
- `GET /v1/invariants`
- `GET /v1/invariants/named`
- `GET /v1/conformance/vectors`

All data is synthetic and marked as staging fixture data. Only GET is accepted. Unknown routes return 404; non-GET methods return 405.

## Local test

Requires Node.js 20 or newer:

```sh
npm test
npm start
```

## Railway

Configure the isolated Railway service to use this repository and branch with root directory `/staging-mock`. Set the start command to `npm start`, health check to `/health`, and do not add production environment variables, databases, volumes, or public domains.

This mock is for adapter protocol and integration testing only. Its responses are not evidence of runtime enforcement or production conformance.
