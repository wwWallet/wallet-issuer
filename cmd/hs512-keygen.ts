import { generateHS512Key } from 'wallet-common';
import fs from 'fs';
import path from 'path';

generateHS512Key().then((res) => {
	fs.writeFileSync(path.join(__dirname, '../keys/secret.hs512.b64'), res.exportedKey, 'utf-8');
	console.log("Generated and stored HS512 key and stored at " + path.join(__dirname, '../keys/secret.hs512.b64'));
});
