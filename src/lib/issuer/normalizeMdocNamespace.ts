import { DateOnly } from '@owf/mdoc';

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

export function normalizeMdocNamespace(
	data: Record<string, unknown>
): Record<string, unknown> {
	return Object.fromEntries(
		Object.entries(data).map(([k, v]) => [k, normalize(v)])
	);
}

function normalize(value: unknown): unknown {
	if (value instanceof Uint8Array) {
		return value;
	}

	if (value instanceof DateOnly) {
		return value;
	}

	if (typeof value === 'string' && ISO_DATE.test(value)) {
		return new DateOnly(value);
	}

	return value;
}
