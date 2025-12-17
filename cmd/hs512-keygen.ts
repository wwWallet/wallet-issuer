import { generateHS512Key } from '../src/lib/core/HS512';

generateHS512Key().then((res) => {
	console.log(res);
});
