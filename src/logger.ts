import winston from 'winston';

const logLevels = {
	levels: {
		error: 0,
		warn: 1,
		info: 2,
		debug: 3,
	},
	colors: {
		error: 'red',
		warn: 'yellow',
		info: 'green',
		debug: 'blue',
	},
};

export const logger = winston.createLogger({
	levels: logLevels.levels,
	transports: [],
});

if (process.env.NODE_ENV === 'production') {
	logger.add(
		new winston.transports.File({
			filename: 'prod.log',
			level: 'warn',
			format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
		}),
	);
	logger.add(
		new winston.transports.Console({
			level: 'error',
			format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
		}),
	);
} else {
	logger.add(
		new winston.transports.Console({
			level: 'debug',
			format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
		}),
	);
}
