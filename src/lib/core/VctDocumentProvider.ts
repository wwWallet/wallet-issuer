import { TypeMetadata } from "wallet-common/dist/schemas/SdJwtVcTypeMetadataSchema";

export interface VctDocumentProvider {
	getVctMetadataDocument(vct: string): Promise<TypeMetadata | null>;
}
