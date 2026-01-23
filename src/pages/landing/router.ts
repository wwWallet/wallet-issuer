import { Router } from 'express';
import { issuer } from '../../vci/issuer';

export const landingRouter = Router();

landingRouter.get('/', async (_req, res) => {
	const metadata = await issuer.getMetadata(false);
	res.render('home', { metadata });
});
