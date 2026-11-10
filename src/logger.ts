import { pino } from 'pino';

const CENSOR = '[redacted]';

const redactPaths = [
	'tx_value',
	'txCode',
	'*.tx_value',
	'*.txCode',
	'access_token',
	'id_token',
	'refresh_token',
	'*.access_token',
	'*.id_token',
	'*.refresh_token',
	'client_secret',
	'*.client_secret',
];

export const logger = pino({
	level: process.env.LOG_LEVEL || 'info',

	redact: {
		paths: redactPaths,
		censor: CENSOR,
	},

	transport:
		process.env.NODE_ENV !== 'production'
			? {
					target: 'pino-pretty',
					options: {
						colorize: true,
						messageFormat: '{if module}[{module}] {end}{msg}',
						ignore: 'pid,hostname,module',
					},
				}
			: undefined,
});
