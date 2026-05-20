import { logger } from "../../logger";

type AnyObj = Record<string, any>;

function base64ToBstr(dataUrl: string): Uint8Array | undefined {
	const base64Data = dataUrl.split(',')[1];
	if (!base64Data) {
		logger.error("Invalid Data URL format. Returning underfined");
		return undefined;
	}
	const buffer = Buffer.from(base64Data, 'base64');
	return new Uint8Array(buffer);
}

export function convertPidSdJwtVcToMdoc(pid: AnyObj) {
	const address = (pid?.address ?? {}) as AnyObj;
	const pob = (pid?.place_of_birth ?? {}) as AnyObj;
	const ageEq = (pid?.age_equal_or_over ?? {}) as AnyObj;

	return {
		family_name: pid?.family_name,
		family_name_birth: pid?.birth_family_name,
		given_name: pid?.given_name,
		given_name_birth: pid?.birth_given_name,

		personal_administrative_number: pid?.personal_administrative_number,

		birth_date: pid?.birthdate,

		issuing_authority: pid?.issuing_authority,
		issuing_country: pid?.issuing_country,
		issuing_jurisdiction: pid?.issuing_jurisdiction,

		document_number: pid?.document_number,

		issuance_date: pid?.date_of_issuance,
		expiry_date: pid?.date_of_expiry,

		age_over_18: ageEq?.["18"],
		age_over_21: ageEq?.["21"],
		age_in_years: pid?.age_in_years,
		age_birth_year: pid?.age_birth_year,

		sex: pid?.sex,

		nationality: pid?.nationalities,

		place_of_birth: pob,

		resident_address: address?.formatted,
		resident_country: address?.country,
		resident_state: address?.region,
		resident_city: address?.locality,
		resident_postal_code: address?.postal_code,
		resident_street: address?.street_address,
		resident_house_number: address?.house_number,

		portrait: base64ToBstr(pid?.picture),

		email_address: pid?.email,
		mobile_phone_number: pid?.phone_number,

		trust_anchor: pid?.trust_anchor,
	};
}
