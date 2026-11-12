import {
	createVctDocumentResolutionEngine,
	VctDocumentProvider,
	VctResolutionErrors,
	ok,
	err,
} from 'wallet-common';
import { config } from './index';
import { logger } from '../src/logger';

const log = logger.child({ module: 'VctRegistry' });

const provider: VctDocumentProvider = {
	getVctMetadataDocument: async (vct: string) => {
		try {
			const url = new URL(config.vctRegistryUrl);
			url.searchParams.append('vct', vct);
			const res = await fetch(url);
			const json = await res.json();
			if (!res) return err(VctResolutionErrors.NotFound);
			return ok(json as any);
		} catch (e) {
			log.error({ err: e, vct }, 'VCT metadata retrieval failed');
			return err(VctResolutionErrors.NotFound);
		}
	},
};

export const vctDocumentProvider = createVctDocumentResolutionEngine([provider]);
