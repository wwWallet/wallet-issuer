document.addEventListener('DOMContentLoaded', () => {
	const canvas = document.getElementById('qr');
	if (!canvas) {
		return;
	}
	const value = canvas.dataset.value || 'Hello World';

	QRCode.toCanvas(canvas, value, {
		width: 200,
		margin: 2,
		errorCorrectionLevel: 'M',
	}).catch((err) => console.error(err));
});
