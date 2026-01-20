import { TypeMetadata } from 'wallet-common/dist/schemas/SdJwtVcTypeMetadataSchema';
import { createVctDocumentResolutionEngine, VctDocumentProvider } from 'wallet-common';
import { config } from './index';
import { logger } from '../src/logger';

const provider: VctDocumentProvider = {
	getVctMetadataDocument: async (vct: string) => {
		try {
			const url = new URL(config.vctRegistryUrl);
			url.searchParams.append('vct', vct);
			const result = await fetch(url);
			const json = await result.json();
			const parsed = TypeMetadata.parse(json);
			return parsed;
		} catch (err) {
			logger.error('Error in VCT SDJWT Metadata retrieval: ' + JSON.stringify(err));
			return null;
		}
	},
};

export const vctDocumentProvider = createVctDocumentResolutionEngine([provider]);
