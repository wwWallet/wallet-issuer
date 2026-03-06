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
export const disclosureFrameMap: DisclosureFrameMap = {};
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
