import { TypeMetadata } from "wallet-common/dist/schemas/SdJwtVcTypeMetadataSchema";

export interface VctRegistry {
	/**
 	* 
  	* @param vct
   	*  @throws
   	*/
	getVctMetadataDocument(vct: string): Promise<TypeMetadata>;
}
