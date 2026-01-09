import { TypeMetadata } from "wallet-common/dist/schemas/SdJwtVcTypeMetadataSchema";
import { VctDocumentProvider } from "../src/lib/core/VctDocumentProvider";
import { config } from './index';


export const vctDocumentProvider: VctDocumentProvider = {
	getVctMetadataDocument: async (vct: string) => {
		try {
			const url = new URL(config.vctRegistryUrl);
			url.searchParams.append('vct', vct);
			const result = await fetch(url);
			const parsed = TypeMetadata.parse(result.json());
			return parsed;	
		}
		catch {
			return null;
		}
	}
}
