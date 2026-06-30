import { generateRandomIdentifier } from "wallet-common";

export function generateNumericPin(length: number = 4): string {
	const array = new Uint8Array(length);
	crypto.getRandomValues(array);
	return Array.from(array, (byte) => (byte % 10).toString()).join('');
}

export function generateRandomIdentifierStrictLength(length: number = 4): string {
	return generateRandomIdentifier(length).slice(0, length);
}
