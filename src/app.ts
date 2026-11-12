import express, { Express, NextFunction, Request, Response } from 'express';
import { config } from '../config';
import path from 'node:path';
import { landingRouter } from './pages/landing/router';
import { aboutRouter } from './pages/about/router';
import { vciRouter } from './vci/router';
import { locale } from '../config/locale';
import { logger } from './logger';
import { HttpLoggerMiddleware } from './middlewares/httpLogger.middleware';
import { issuer } from './vci/issuer';
import { apiRouter } from './api/router';

const log = logger.child({ module: 'App' });

const app: Express = express();

if (config.logHttp) {
	app.use(HttpLoggerMiddleware);
}

app.get('/.well-known/openid-credential-issuer/openid', async (_req, res) => {
	try {
		const { metadata } = await issuer.getMetadata();
		res.status(200).send(metadata);
	} catch (e) {
		log.error({ err: e }, 'Failed to build credential issuer metadata');
		res.status(500).send({ error: 'internal_server_error' });
	}
});

app.get('/.well-known/jwt-vc-issuer/openid', async (_req, res) => {
	try {
		const { jwtVcIssuerMetadata } = await issuer.getMetadata();
		res.status(200).send(jwtVcIssuerMetadata);
	} catch (e) {
		log.error({ err: e }, 'Failed to build JWT VC issuer metadata');
		res.status(500).send({ error: 'internal_server_error' });
	}
});

app.use('/openid', vciRouter);

app.use('/api', apiRouter);

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
		start_url: '/',
		display: 'standalone',
		background_color: config.siteConfig.background_color,
		theme_color: config.siteConfig.theme_color,
		icons: [
			{
				src: '/images/favicon-192x192.png',
				sizes: '192x192',
				type: 'image/png',
			},
			{
				src: '/images/favicon-512x512.png',
				sizes: '512x512',
				type: 'image/png',
			},
		],
	};

	res.setHeader('Content-Type', 'application/manifest+json');
	return res.send(manifest);
});

app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
	if (res.headersSent) {
		return next(err);
	}

	// pino-http (LOG_HTTP=true) picks this up and logs the real error instead of a generic 500
	if (err instanceof Error) {
		res.err = err;
	} else {
		res.err = new Error(String(err));
	}

	// Respect the status attached to the error (e.g. by body-parser or http-errors),
	// falling back to 500 if there is none or it is not a valid error status
	let errStatus: unknown;
	if (typeof err === 'object' && err !== null) {
		if ('status' in err) {
			errStatus = err.status;
		} else if ('statusCode' in err) {
			errStatus = err.statusCode;
		}
	}

	let status = 500;
	if (
		typeof errStatus === 'number' &&
		Number.isInteger(errStatus) &&
		errStatus >= 400 &&
		errStatus <= 599
	) {
		status = errStatus;
	}

	if (status >= 500) {
		log.error({ err }, 'Unhandled error in request handler');
		res.status(status).send({ error: 'internal_server_error' });
	} else {
		log.warn({ err, status }, 'Client error in request handler');
		res.status(status).send({ error: 'bad_request' });
	}
});

process.on('unhandledRejection', (reason) => {
	log.fatal({ err: reason }, 'Unhandled promise rejection, exiting');
	logger.flush(() => process.exit(1));
});

process.on('uncaughtException', (err) => {
	log.fatal({ err }, 'Uncaught exception, exiting');
	logger.flush(() => process.exit(1));
});

app.listen(config.port, () => {
	log.info({ url: config.url, port: config.port }, 'Issuer listening');
});
