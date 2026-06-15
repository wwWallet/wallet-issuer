import { DateOnly, DeviceKey, DeviceKeyInfoOptions, KeyAuthorizations, KeyAuthorizationsOptions, ValidityInfoOptions } from "@owf/mdoc";
import { JWK } from "jose";

type AnyObj = Record<string, any>;

const credentialConfigurationsThatIncludeExpectedUpdate = ["etsi:eaa:mdoc:2"];

const credentialConfigurationKeyAuthorizationOptions: Record<string, KeyAuthorizationsOptions> = {
	"etsi:eaa:mdoc:6": {
		namespaces: ["org.iso.23220.1", "org.etsi.01947201.010101"]
	},
	"etsi:eaa:mdoc:7": {
		dataElements: new Map([
			["org.iso.23220.1", ["given_name", "family_name"]]
		])
	},
	"etsi:eaa:mdoc:8": {
		namespaces: ["org.etsi.01947201.010101"],
		dataElements: new Map([
			["org.iso.23220.1", ["given_name", "family_name"]]
		])
	}
}

function getEtsiTestCase(scope: string): number {
	const potentialNumberFromScope = scope.split(':').pop();
	if (Number.isNaN(Number(potentialNumberFromScope))) {
		console.log("Could not find ETSI test case number.");
		return 0;
	}
	return Number(potentialNumberFromScope);
}

export function getEtsiEaaClaims(etsiClaims: AnyObj, scope: string, vct?: string | undefined ) {
	if (scope.includes("sjv")) {
		return getEtsiEaaVctClaims(etsiClaims, scope, vct);
	}
	else if (scope.includes("mdoc")) {
		return getEtsiEaaMdocClaims(etsiClaims, scope);
	}
	else {
		throw new Error("Invalid scope " + scope);
	}
}

export function getEtsiEaaVctClaims(etsiClaims: AnyObj, scope: string, vct: string | undefined) {
	switch(getEtsiTestCase(scope)) {
		case 1:
			return {
				vct: vct,
				issuing_authority: etsiClaims.issuing_authority,
				given_name: etsiClaims.given_name,
				family_name: etsiClaims.family_name
			};
		case 2:
			return {
				vct: vct,
				issuing_authority: etsiClaims.issuing_authority,
				given_name: etsiClaims.given_name,
				family_name: etsiClaims.family_name
			};
		case 3:
			return {
				vct: vct,
				issuing_authority: etsiClaims.issuing_authority,
				issuing_country: etsiClaims.issuing_country,
				iss_reg_id: etsiClaims.iss_reg_id,
				given_name: etsiClaims.given_name,
				family_name: etsiClaims.family_name
			};
		case 4:
			return {
				vct: vct,
				issuing_authority: etsiClaims.issuing_authority,
				issuing_country: etsiClaims.issuing_country,
				iss_reg_id: etsiClaims.iss_reg_id,
				also_known_as: etsiClaims.also_known_as
			};
		case 5:
			return {
				vct: vct,
				issuing_authority: etsiClaims.issuing_authority,
				issuing_country: etsiClaims.issuing_country,
				iss_reg_id: etsiClaims.iss_reg_id,
				given_name: etsiClaims.given_name,
				family_name: etsiClaims.family_name,
				oneTime: etsiClaims.oneTime
			};
		case 6:
			return {
				vct: vct,
				issuing_authority: etsiClaims.issuing_authority,
				issuing_country: etsiClaims.issuing_country,
				iss_reg_id: etsiClaims.iss_reg_id,
				given_name: etsiClaims.given_name,
				family_name: etsiClaims.family_name,
				shortLived: etsiClaims.shortLived
			};
		case 7:
			return {
				vct: vct,
				issuing_authority: etsiClaims.issuing_authority,
				issuing_country: etsiClaims.issuing_country,
				iss_reg_id: etsiClaims.iss_reg_id,
				given_name: etsiClaims.given_name,
				family_name: etsiClaims.family_name,
				iat: etsiClaims.iat
			};
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		default:
			return {
				vct: vct,
				given_name: etsiClaims.given_name,
				family_name: etsiClaims.family_name,
				place_of_birth: etsiClaims.place_of_birth,
				places_of_residence: etsiClaims.places_of_residence,
				nationalities: etsiClaims.nationalities
			};
	}
}

export function getEtsiEaaMdocClaims(etsiClaims: AnyObj, scope: string) {
	switch(getEtsiTestCase(scope)) {
		case 1:
			return {
				family_name: etsiClaims.family_name,
				given_name: etsiClaims.given_name,
				birth_date: new Map([["birth_date", new DateOnly(etsiClaims.birth_date)]]),
				issue_date: etsiClaims.issue_date,
				expiry_date: etsiClaims.expiry_date,
				issuing_country: etsiClaims.issuing_country,
				issuing_authority_unicode: etsiClaims.issuing_authority_unicode,
				document_number: etsiClaims.document_number,
			};
		case 2:
			return {
				family_name: etsiClaims.family_name,
				given_name: etsiClaims.given_name,
				birth_date: new Map([["birth_date", new DateOnly(etsiClaims.birth_date)]]),
				issue_date: etsiClaims.issue_date,
				expiry_date: etsiClaims.expiry_date,
				issuing_country: etsiClaims.issuing_country,
				issuing_authority_unicode: etsiClaims.issuing_authority_unicode,
				document_number: etsiClaims.document_number,
				iss_reg_id: etsiClaims.iss_reg_id
			};
		case 3:
			return {
				birth_date: new Map([["birth_date", new DateOnly(etsiClaims.birth_date)]]),
				issue_date: etsiClaims.issue_date,
				expiry_date: etsiClaims.expiry_date,
				issuing_country: etsiClaims.issuing_country,
				issuing_authority_unicode: etsiClaims.issuing_authority_unicode,
				also_known_as: etsiClaims.also_known_as
			};
		case 4:
			return {
				family_name: etsiClaims.family_name,
				given_name: etsiClaims.given_name,
				birth_date: new Map([["birth_date", new DateOnly(etsiClaims.birth_date)]]),
				issue_date: etsiClaims.issue_date,
				expiry_date: etsiClaims.expiry_date,
				issuing_country: etsiClaims.issuing_country,
				issuing_authority_unicode: etsiClaims.issuing_authority_unicode,
				document_number: etsiClaims.document_number,
				oneTime: 'oneTime' in etsiClaims ? true : false
			};
		case 5:
			return {
				family_name: etsiClaims.family_name,
				given_name: etsiClaims.given_name,
				birth_date: new Map([["birth_date", new DateOnly(etsiClaims.birth_date)]]),
				issue_date: etsiClaims.issue_date,
				expiry_date: etsiClaims.expiry_date,
				issuing_country: etsiClaims.issuing_country,
				issuing_authority_unicode: etsiClaims.issuing_authority_unicode,
				document_number: etsiClaims.document_number,
				shortLived: 'shortLived' in etsiClaims ? true : false
			};
		case 10:
			return {
				family_name: etsiClaims.family_name,
				given_name: etsiClaims.given_name,
				birth_date: new Map([["birth_date", new DateOnly(etsiClaims.birth_date)]]),
				issue_date: etsiClaims.issue_date,
				expiry_date: etsiClaims.expiry_date,
				issuing_country: etsiClaims.issuing_country,
				issuing_authority_unicode: etsiClaims.issuing_authority_unicode,
				document_number: etsiClaims.document_number,
				resident_country: etsiClaims.resident_country
			};
		case 6:
		case 7:
		case 8:
		default:
			return {
				family_name: etsiClaims.family_name,
				given_name: etsiClaims.given_name,
				birth_date: new Map([["birth_date", new DateOnly(etsiClaims.birth_date)]]),
				issue_date: etsiClaims.issue_date,
				expiry_date: etsiClaims.expiry_date,
				issuing_country: etsiClaims.issuing_country,
				issuing_authority_unicode: etsiClaims.issuing_authority_unicode,
				document_number: etsiClaims.document_number,
			};
	}
}

export function getValidityInfoOptions(credentialConfigurationId: string): ValidityInfoOptions {
	const signed = new Date();
	const validFromDate = new Date(signed.getTime() + 1000);

	const expirationDate = new Date();
	expirationDate.setFullYear(expirationDate.getFullYear() + 1);

	const expectedUpdate = new Date();
	expectedUpdate.setMonth(expectedUpdate.getMonth() + 3);

	let validityInfo: ValidityInfoOptions = {
		signed,
		validFrom: validFromDate,
		validUntil: expirationDate
	}
	if (credentialConfigurationsThatIncludeExpectedUpdate.includes(credentialConfigurationId)) {
		validityInfo.expectedUpdate = expectedUpdate;
	}

	return validityInfo;

}

export function getDeviceKeyInfoOptions(credentialConfigurationId: string, holderPublicKeyJwk: JWK): DeviceKeyInfoOptions {

	let deviceKeyInfo: DeviceKeyInfoOptions = {
		deviceKey: DeviceKey.fromJwk(holderPublicKeyJwk as Record<string, unknown>)
	};


	let keyAuthorizationsOptions: KeyAuthorizationsOptions = {};
	if(Object.keys(credentialConfigurationKeyAuthorizationOptions).includes(credentialConfigurationId)) {
		keyAuthorizationsOptions = credentialConfigurationKeyAuthorizationOptions[credentialConfigurationId];
	}

	deviceKeyInfo.keyAuthorizations = KeyAuthorizations.create(keyAuthorizationsOptions);

	return deviceKeyInfo;
}
