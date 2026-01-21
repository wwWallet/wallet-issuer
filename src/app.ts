import express, { Express } from 'express';
import { config } from '../config';
import path from 'node:path';
import { landingRouter } from './pages/landing/router';
import { aboutRouter } from './pages/about/router';
import { vciRouter } from './vci/router';
import { locale } from '../config/locale';

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

app.use((req, res, next) => {
	res.locals.locale = locale;
	res.locals.currentPath = req.path;
	next();
});

app.use('/', landingRouter);
app.use('/', aboutRouter);

app.get('/metadata/:filename', (req, res) => {
	if (req.params.filename !== 'site.webmanifest') {
		return res.status(404).send();
	}
	const manifest = {
		name: config.siteConfig.name,
		short_name: config.siteConfig.short_name,
		start_url: "/",
		display: "standalone",
		background_color: config.siteConfig.background_color,
		theme_color: config.siteConfig.theme_color,
		icons: [
			{
				src: "/images/favicon-192x192.png",
				sizes: "192x192",
				type: "image/png"
			},
			{
				src: "/images/favicon-512x512.png",
				sizes: "512x512",
				type: "image/png"
			}
		]
	};

	res.setHeader('Content-Type', 'application/manifest+json');
	return res.send(manifest);
});

app.listen(config.port, () => {
	console.log(`Nodejs service listening on ${config.url}`);
});
