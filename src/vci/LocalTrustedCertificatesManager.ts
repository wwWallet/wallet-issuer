import path from 'path';
import fs from 'node:fs/promises';

export interface TrustedCertificatesManager {
	getAllPemCertificates(): Promise<string[]>;
}

export const LocalTrustedCertificatesManager = (): TrustedCertificatesManager => {
	const dirPath = path.join(__dirname, '../../../certs');

	fs.access(dirPath).catch(() => {
		throw new Error(`Directory ${dirPath} is required`);
	});
	return {
		getAllPemCertificates: async () => {
			const files = await fs.readdir(dirPath);
			const pemFiles = files.filter((f) => f.toLowerCase().endsWith('.pem'));
			const contents = await Promise.all(
				pemFiles.map(async (file) => {
					return fs.readFile(path.join(dirPath, file), 'utf8');
				}),
			);
			return contents;
		},
	};
};
