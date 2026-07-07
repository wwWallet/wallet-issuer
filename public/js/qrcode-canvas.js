document.addEventListener('DOMContentLoaded', () => {
	const canvas = document.getElementById('qr');
	if (!canvas) {
		return;
	}
	const value = canvas.dataset.value;

	QRCode.toCanvas(canvas, value, {
		width: 220,
		margin: 2,
		errorCorrectionLevel: 'M',
	}).catch((err) => console.error(err));
});
