import { Router } from 'express';
import { issuer } from '../../vci/issuer';
import { fromBase64Url } from 'wallet-common/dist/utils/util';
import { config } from '../../../config';
import { logger } from '../../logger';

export const landingRouter = Router();
const decoder = new TextDecoder();

landingRouter.get('/', async (_req, res) => {
	const { metadata } = await issuer.getMetadata();
	res.render('home', { metadata });
});

landingRouter.get('/offer/:id', async (req, res) => {
	const credentialConfigurationIdB54U = req.params.id;
	if (!credentialConfigurationIdB54U) {
		res.redirect('/');
		return;
	}
	const credentialConfigurationId = decoder.decode(fromBase64Url(credentialConfigurationIdB54U));
	const { metadata } = await issuer.getMetadata();
	const targetMetadata = metadata.credential_configurations_supported?.[credentialConfigurationId];

	// Default: use the configuration id itself
	let credentialName = credentialConfigurationId;

	// If a display name exists, prefer it
	const displayArr = targetMetadata?.credential_metadata?.display;
	if (Array.isArray(displayArr) && displayArr.length > 0) {
		const d = displayArr[0];
		if (typeof d?.name === "string" && d.name.trim()) {
			credentialName = d.name;
		}
	}

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
	res.render('offer', { credentialOfferWithReference, credentialOfferWithReferenceForWwwallet, credentialName });
});
