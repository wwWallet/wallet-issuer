import { Router } from 'express';

export const aboutRouter = Router();

aboutRouter.get('/about', (req, res) => {
	const protocol = (req.headers['x-forwarded-proto'] as string) || req.protocol;
	const host = req.get('host');
	const baseUrl = `${protocol}://${host}`;

	res.render('about', {
		title: 'About',
		baseUrl,
	});
});
