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
		const parsedPreAuthorizedCode = parsedBody["pre-authorized_code"];
		const parsedTxCode = parsedBody["tx_code"];

		const grant = await issuer.preAuthorizedCodeStore.consume(parsedPreAuthorizedCode);
		const expectedTxCodeStructure = grant?.tx_code;
		const expectedTxCodeValue = grant?.tx_value;
		const expectedExpDateMs = grant?.exp;

		if (!grant) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_grant', 'Missing or already consumed grant.');
		}

		if (!expectedTxCodeStructure && parsedTxCode) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_request', 'Missing tx_code.');
		}

		if (expectedTxCodeStructure && !parsedTxCode) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_request', 'Provided tx_code while grant does not expect it.');
		}

		if (expectedTxCodeStructure && String(expectedTxCodeValue) !== String(parsedTxCode)) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_grant', 'Invalid tx_code.');
		}

		if (expectedExpDateMs && expectedExpDateMs < Date.now()) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_grant', 'Expired grant.');
		}

		return res.status(200).send(grant);
	} catch (error) {
		if (error instanceof ZodError) {
			return sendPreAuthorizedCodeHandlerError(res, 400, 'invalid_request', 'Missing or invalid parameters');
		}

		console.log(`Error sending pre-authorized code: ${error}`);
		return sendPreAuthorizedCodeHandlerError(res, 500, 'server_error', 'An unexpected error occurred');
	}
};
