# wwWallet Issuer
wwWallet Issuer is a standalone digital credential issuer implementing OpenID4VCI.

> [!NOTE]
> To quickly setup the **wwWallet** ecosystem see https://github.com/wwWallet/wwwallet

## How to run

Install dependencies
```
yarn install
```

Run in dev mode
```
yarn run dev
```

## API authentication

Enable the credential offer creation endpoint and configure the bearer token used for all
`/api/*` endpoints:

```dotenv
CREDENTIAL_OFFER_API_ENABLED=true
CREDENTIAL_OFFER_API_BEARER_TOKEN=replace-with-a-random-secret
```

Send the token with every `/api/*` request:

```http
Authorization: Bearer replace-with-a-random-secret
Content-Type: application/json
```

The issuer refuses to start when the API is enabled without a bearer token. Routes outside
`/api`, including the generated `GET /openid/credential-offer/:id` URL, remain public.

For a pre-authorized offer, the authenticated API client supplies an opaque subject identifier:

```json
{
  "credential_configuration_ids": ["urn:eudi:pid:1:dc"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "account_id": "issuance-transaction-123"
    }
  }
}
```

Possession of `CREDENTIAL_OFFER_API_BEARER_TOKEN` authorizes the caller to select any
`account_id`, so restrict this endpoint to trusted backend clients and protect the token as a
high-privilege credential. The value becomes the access token subject (`sub`) and is sent
unchanged to the remote claims fetcher. It should be an opaque reference, not sensitive claims
data.

## Remote claims fetching

Enable remote claims fetching explicitly:

```dotenv
VC_CLAIMS_FETCHER_ENABLED=true
VC_CLAIMS_FETCHER_URL=https://example.com/claims
VC_CLAIMS_FETCHER_API_KEY=replace-with-a-random-secret
```

When `VC_CLAIMS_FETCHER_ENABLED` is not `true`, the issuer uses filesystem claims even if
`VC_CLAIMS_FETCHER_URL` and `VC_CLAIMS_FETCHER_API_KEY` are present.

## Local credential configuration overrides

You can add local-only credential configurations without changing tracked files.

1. Create a local config `supportedCredentialConfigurations.local.ts` file like the following:
```
import { OpenidCredentialIssuerMetadata, VerifiableCredentialFormat } from 'wallet-common';

type CredentialConfigurationsSupported = OpenidCredentialIssuerMetadata['credential_configurations_supported'];
type DisclosureFrameMap = Record<string, Record<string, unknown>>;

// Copy to `supportedCredentialConfigurations.local.ts` and edit locally.
export const supportedCredentialConfigurations: CredentialConfigurationsSupported = {
  'urn:credential:example': {
    scope: 'example',
    vct: 'urn:credential:example',
    format: VerifiableCredentialFormat.DC_SDJWT,
  },
};

// Optional: add disclosure frames keyed by credential configuration id.
export const disclosureFrameMap: DisclosureFrameMap = {
  'urn:credential:example': {
    family_name: true,
    given_name: true,
    picture: true,
  },
};
```
2. Restart the issuer.

Notes:
- `config/*.local.ts` is ignored by git in this repo.
- Local entries are merged into the base `supportedCredentialConfigurations` at runtime.
- If a local credential configuration id matches a base one, the local one overrides it.

## Pre-commit

We use [pre-commit](https://pre-commit.com/) to enforce our `.editorconfig` (newline at EOF, no bad indentation, etc.) before code is committed.

#### One-time setup

```
# install pre-commit if you don’t already have it
pip install pre-commit       # or brew install pre-commit / pipx install pre-commit

# enable the git hook in this repo
pre-commit install

# optional: clean up the repo on demand
pre-commit run --all-files
git add -A
```

#### What happens on commit

- Auto-fixers run (e.g. add final newlines).
- After the auto-fixers, the editorconfig-checker runs inside Docker to validate all staged files.
- If violations remain, fix them manually until the commit passes.
