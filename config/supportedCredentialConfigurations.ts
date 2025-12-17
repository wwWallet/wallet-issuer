import { OpenidCredentialIssuerMetadata } from "wallet-common";
import { VerifiableCredentialFormat } from "wallet-common/dist/types";

// In this object, all the cryptographic-related attributes can be ommited
// because default values will be used by the issuer module
export const supportedCredentialConfigurations: OpenidCredentialIssuerMetadata["credential_configurations_supported"] = {
  "urn:eudi:pid:1:dc": {
    "scope": "pid:sd_jwt_dc",
    "vct": "urn:eudi:pid:1",
    "format": VerifiableCredentialFormat.DC_SDJWT,

    // define proof_types_supported only to require attestations
    "proof_types_supported": {
      "attestation": {
      	"key_attestations_required": {}
      } as any, // force 'any' to avoid re-defining other elements of "proof_types_supported"

    },
  },
  "eu.europa.ec.eudi.pid.1": {
    "scope": "pid:mso_mdoc",
    "doctype": "eu.europa.ec.eudi.pid.1",
    "display": [
      {
        "name": "PID mDoc",
        "description": "Person Identification Data",
        "background_image": {
          "uri": "https://demo-issuer.wwwallet.org/images/background-image.png"
        },
        "background_color": "#4CC3DD",
        "text_color": "#000000",
        "locale": "en-US"
      }
    ],
    "format": VerifiableCredentialFormat.MSO_MDOC,
    "claims": [
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "family_name"
        ],
        "mandatory": true,
        "display": [
          {
            "name": "Family Name",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "given_name"
        ],
        "mandatory": true,
        "display": [
          {
            "name": "Given Name(s)",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "birth_date"
        ],
        "mandatory": true,
        "display": [
          {
            "name": "Birth Date",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "birth_place"
        ],
        "mandatory": true,
        "display": [
          {
            "name": "Birth Place",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "nationality"
        ],
        "mandatory": true,
        "display": [
          {
            "name": "Nationality",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_address"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Resident Address",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_country"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Resident Country",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_state"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Resident State",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_city"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Resident City",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_postal_code"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Resident Postal Code",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_street"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Resident Street",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_house_number"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Resident House Number",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "personal_administrative_number"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Personal Administrative Number",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "portrait"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Portrait Image",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "family_name_birth"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Birth Family Name(s)",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "given_name_birth"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Birth Given Name(s)",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "sex"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Sex",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "email_address"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Email Address",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "mobile_phone_number"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Mobile Phone Number",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "expiry_date"
        ],
        "mandatory": true,
        "display": [
          {
            "name": "Expiry Date",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "issuing_authority"
        ],
        "mandatory": true,
        "display": [
          {
            "name": "Issuance Authority",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "issuing_country"
        ],
        "mandatory": true,
        "display": [
          {
            "name": "Issuing Country",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "document_number"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Document Number",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "issuing_jurisdiction"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Issuing Jurisdiction",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "issuance_date"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Issuance Date",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "age_over_18"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Age Over 18",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "age_in_years"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Age in Years",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "age_birth_year"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Age Year of Birth",
            "locale": "en-US"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "trust_anchor"
        ],
        "mandatory": false,
        "display": [
          {
            "name": "Trust Anchor",
            "locale": "en-US"
          }
        ]
      }
    ]
  },
  "urn:credential:diploma": {
    "scope": "diploma",
    "vct": "urn:credential:diploma",
    "format": VerifiableCredentialFormat.DC_SDJWT,
  },
  "urn:eudi:ehic:1": {
    "scope": "ehic",
    "vct": "urn:eudi:ehic:1",
    "format": VerifiableCredentialFormat.DC_SDJWT,
  },
  "urn:eu.europa.ec.eudi:por:1": {
    "scope": "por:sd_jwt_vc",
    "vct": "urn:eu.europa.ec.eudi:por:1",
    "format": VerifiableCredentialFormat.DC_SDJWT,
  },
  "urn:eu.europa.ec.eudi:por:1:deferred": {
    "scope": "por:sd_jwt_vc",
    "format": VerifiableCredentialFormat.DC_SDJWT,
    "vct": "urn:eu.europa.ec.eudi:por:1",
  }
}
