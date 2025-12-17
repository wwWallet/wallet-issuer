import { generateECDHKeypair } from "../src/lib/core/ECDH-ES";

generateECDHKeypair().then((res) => {
	console.log(JSON.stringify(res));
});