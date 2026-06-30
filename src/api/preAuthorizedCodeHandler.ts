import express from 'express';
import { issuer } from "../vci/issuer";
import z, { ZodError } from 'zod';

const sendPreAuthorizedCodeHandlerError = (
	res: express.Response,
	status: 400 | 500,
	error: 'invalid_request' | 'invalid_grant' | 'server_error',
	errorDescription: string,
) => {
	return res.status(status).send({
		error,
		error_description: errorDescription,
	});
};

const preAuthorizedCodeHandlerSchema = z.object({
	"pre-authorized_code": z.string().min(1),
	"tx_code": z.string().optional(),
});

export const preAuthorizedCodeHandler = async (req: express.Request, res: express.Response) => {
	try {

		const parsedBody = preAuthorizedCodeHandlerSchema.parse(req.body);
		const preAuthorizedCode = parsedBody["pre-authorized_code"];
		const txCode = parsedBody["tx_code"];

		const grant = await issuer.preAuthorizedCodeStore.get(preAuthorizedCode);

		if (!grant) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_grant', 'Missing or already consumed grant.');
		}

		if (!grant.tx_code && txCode) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_request', 'Missing tx_code.');
		}

		if (grant.tx_code && !txCode) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_request', 'Provided tx_code while grant does not expect it.');
		}

		if (grant.tx_code && String(grant.tx_value) !== String(txCode)) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_grant', 'Invalid tx_code.');
		}

		if (grant.exp && grant.exp < Date.now()) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_grant', 'Expired grant.');
		}

		await issuer.preAuthorizedCodeStore.delete(preAuthorizedCode);

		return res.status(200).send(grant);
	} catch (error) {
		if (error instanceof ZodError) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_request', 'Missing or invalid parameters');
		}

		console.log(`Error sending pre-authorized code: ${error}`);
		return sendPreAuthorizedCodeHandlerError(res, 500, 'server_error', 'An unexpected error occurred');
	}
};
