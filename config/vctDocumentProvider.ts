import { createVctDocumentResolutionEngine, VctDocumentProvider, VctResolutionErrors, ok, err } from 'wallet-common';
import { config } from './index';
import { logger } from '../src/logger';

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
			logger.error('Error in VCT SDJWT Metadata retrieval: ' + JSON.stringify(e));
			return err(VctResolutionErrors.NotFound)
		}
	},
};

export const vctDocumentProvider = createVctDocumentResolutionEngine([provider]);
