document.addEventListener("DOMContentLoaded", () => {
	const input = document.getElementById("offer-url");
	const btn = document.getElementById("copy-offer");

	if (!input || !btn) return;

	btn.addEventListener("click", async () => {
		try {
			await navigator.clipboard.writeText(input.value);
			btn.textContent = "Copied";
			setTimeout(() => (btn.textContent = "Copy"), 1500);
		} catch {
			input.select();
			document.execCommand("copy");
		}
	});
});
