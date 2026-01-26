import { Router } from 'express';
import { issuer } from '../../vci/issuer';
import { fromBase64Url } from 'wallet-common/dist/utils/util';
import { config } from '../../../config';
import { logger } from '../../logger';

export const landingRouter = Router();
const decoder = new TextDecoder();

landingRouter.get('/', async (_req, res) => {
	const metadata = await issuer.getMetadata();
	res.render('home', { metadata });
});

landingRouter.get('/offer/:id', async (req, res) => {
	const credentialConfigurationIdB54U = req.params.id;
	if (!credentialConfigurationIdB54U) {
		res.redirect('/');
		return;
	}
	const credentialConfigurationId = decoder.decode(fromBase64Url(credentialConfigurationIdB54U));
	const { credentialOfferWithReference } = await issuer.generateCredentialOffer({ credentialConfigurationId: credentialConfigurationId });
	const ref = credentialOfferWithReference.searchParams.get('credential_offer_uri');
	const credentialOfferWithReferenceForWwwallet = new URL(config.wwwalletURL);
	if (ref) {
		credentialOfferWithReferenceForWwwallet.searchParams.append('credential_offer_uri', ref);
	}
	else {
		logger.error("No credential offer refference found");
		res.render('error', { error: "invalid-credential-offer" });
		return;
	}
	res.render('qr', { credentialOfferWithReference, credentialOfferWithReferenceForWwwallet });
});
