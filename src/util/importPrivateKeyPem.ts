import { importPKCS8 } from 'jose';
import { logger } from '../logger';

const log = logger.child({ module: 'Keys' });

export async function importPrivateKeyPem(privateKeyPEM: string, algorithm: string) {
	try {
		const privateKey = await importPKCS8(privateKeyPEM, algorithm, { extractable: true });
		return privateKey;
	} catch (err) {
		log.error({ err, algorithm }, 'Failed to import private key');
	}
}
