import { TypeMetadata } from "wallet-common/dist/schemas/SdJwtVcTypeMetadataSchema";
import { VctRegistry } from "../src/lib/core/VctRegistry";
import { config } from './index';


export const vctRegistry: VctRegistry = {
	getVctMetadataDocument: async (vct: string) => {
		const url = new URL(config.vctRegistryUrl);
		url.searchParams.append('vct', vct);
		const result = await fetch(url);
		const parsed = TypeMetadata.parse(result.json());
		return parsed;
	}
}
