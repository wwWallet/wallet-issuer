export function generateNumericPin(length: number = 4): string {
	const array = new Uint8Array(length);
	crypto.getRandomValues(array);
	return Array.from(array, (byte) => (byte % 10).toString()).join('');
}
