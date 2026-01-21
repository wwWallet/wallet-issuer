import express, { Express } from 'express';
import { config } from '../config';
import path from 'node:path';
import { landingRouter } from './pages/landing/router';
import { vciRouter } from './vci/router';

const app: Express = express();

app.use('/openid', vciRouter);

app.use(
	'/images',
	express.static(path.join(__dirname, '../../public/images'), {
		maxAge: '30d',
		immutable: true,
	}),
);

app.use(express.static(path.join(__dirname, '../../public')));

app.set('view engine', 'pug');
app.set('views', path.join(__dirname, '../../views'));

app.use('/', landingRouter);

app.listen(config.port, () => {
	console.log(`Nodejs service listening on ${config.url}`);
});
