document.addEventListener("DOMContentLoaded", () => {
	const input = document.getElementById("offer-url");
	const btn = document.getElementById("copy-offer");

	if (!input || !btn) return;

	const label = btn.querySelector(".btn-copy__text") || btn;
	const defaultLabel = btn.dataset.labelDefault || label.textContent || "Copy";
	const copiedLabel = btn.dataset.labelCopied || "Copied";
	let resetTimer;

	const showCopied = () => {
		window.clearTimeout(resetTimer);
		label.textContent = copiedLabel;
		resetTimer = window.setTimeout(() => {
			label.textContent = defaultLabel;
		}, 1500);
	};

	btn.addEventListener("click", async () => {
		try {
			if (navigator.clipboard && navigator.clipboard.writeText) {
				await navigator.clipboard.writeText(input.value);
			} else {
				input.select();
				document.execCommand("copy");
			}
			showCopied();
		} catch {
			input.select();
			document.execCommand("copy");
			showCopied();
		}
	});
});
