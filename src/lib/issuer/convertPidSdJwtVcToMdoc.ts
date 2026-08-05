import { logger } from "../../logger";

type AnyObj = Record<string, any>;

function pictureDataUrlToBstr(value: unknown): Uint8Array | undefined {
	if (typeof value !== 'string') return undefined;
	const match = /^data:image\/(jpeg|jp2);base64,([a-z0-9+/]+={0,2})$/i.exec(value);
	if (!match) {
		logger.error("PID picture must be a Base64-encoded JPEG or JPEG 2000 data URL");
		return undefined;
	}
	const buffer = Buffer.from(match[2], 'base64');
	if (buffer.length === 0) return undefined;
	const isJpeg = buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
	const isJp2 =
		(buffer[0] === 0xff && buffer[1] === 0x4f && buffer[2] === 0xff && buffer[3] === 0x51) ||
		(buffer.length >= 12 && buffer.subarray(0, 12).equals(Buffer.from([0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a])));
	if ((match[1].toLowerCase() === 'jpeg' && !isJpeg) || (match[1].toLowerCase() === 'jp2' && !isJp2)) {
		logger.error("PID picture contents do not match the declared image media type");
		return undefined;
	}
	return new Uint8Array(buffer);
}

export function convertPidSdJwtVcToMdoc(pid: AnyObj) {
	const address = (pid?.address ?? {}) as AnyObj;
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

		place_of_birth: pid.place_of_birth,

		resident_address: address?.formatted,
		resident_country: address?.country,
		resident_state: address?.region,
		resident_city: address?.locality,
		resident_postal_code: address?.postal_code,
		resident_street: address?.street_address,
		resident_house_number: address?.house_number,

		// ARF PID mdoc uses a CBOR byte string; the data URL exists only in the
		// source SD-JWT representation and must not be copied into the mdoc.
		portrait: pictureDataUrlToBstr(pid?.picture),

		email_address: pid?.email,
		mobile_phone_number: pid?.phone_number,

		trust_anchor: pid?.trust_anchor,
	};
}
