import { generateECDHKeypair } from "wallet-common";
import fs from 'fs';
import path from 'path';

generateECDHKeypair().then((res) => {	
	fs.writeFileSync(path.join(__dirname, '../keys/private.enc.ecdh.jwk'), JSON.stringify(res.privateKeyJwk), 'utf-8');
	fs.writeFileSync(path.join(__dirname, '../keys/public.enc.ecdh.jwk'), JSON.stringify(res.publicKeyJwk), 'utf-8');
	console.log("Generated and stored ECDH-ES keypair at " + path.join(__dirname, '../keys'));
});