import { FindAccount } from "../src/lib/issuer/Account/FindAccount";
import fs from 'node:fs/promises';
import path from 'path';

type AccountEntry = {
	id: string;
	pid: Record<string, unknown>;
	diploma: Record<string, unknown>;
	ehic: Record<string, unknown>;
	por: Record<string, unknown>;
};

const getAccountEntryById = async (id: string): Promise<AccountEntry | null> => {
	const data = await fs.readFile(path.join(__dirname, "../dataset/dataset.json"), 'utf-8');
	return (JSON.parse(data.toString()).filter(((r: AccountEntry) => r.id === id))[0] ?? null) as AccountEntry | null;
}

export const findAccount: FindAccount = async (_ctx, sub, _token) => {

	const acc = await getAccountEntryById(sub);
	if (!acc) {
		return undefined;
	}

	return {
		accountId: acc.id,
		async claims(_use, scope, _claims, _rejected) {
			let releasedClaims = { };
			if (scope.split(' ').includes('pid')) {
				releasedClaims = { pid: acc.pid };
			}
			if (scope.split(' ').includes('ehic')) {
				releasedClaims = { ...releasedClaims, ehic: acc.ehic };
			}
			if (scope.split(' ').includes('diploma')) {
				releasedClaims = { ...releasedClaims, diploma: acc.diploma };
			}
			if (scope.split(' ').includes('por')) {
				releasedClaims = { ...releasedClaims, por: acc.por };
			}
		    // you can pick which claims to return based on `use`, `scope`, etc.
		    // For example, return email & name when scope allows it:
		    return {
			    sub: acc.id,
				...releasedClaims,
		    };
		},
	};
}
