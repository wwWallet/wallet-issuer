(() => {
	const flowInputs = document.querySelectorAll('input[name="issuance-flow"]');
	const actionLinks = document.querySelectorAll(".card-issue-action");

	if (!flowInputs.length || !actionLinks.length) {
		return;
	}

	const selectedFlow = () => {
		const checkedInput = document.querySelector('input[name="issuance-flow"]:checked');
		return checkedInput ? checkedInput.value : "preauth";
	};

	const applyFlowToLink = (link, flow) => {
		const flowKey = flow === "preauth" ? "preauth" : "standard";
		const meta = link.querySelector("[data-action-meta]");

		link.href = link.dataset[`${flowKey}Href`];

		if (meta) {
			meta.textContent = link.dataset[`${flowKey}Meta`];
		}
	};

	const updateCardActions = (flow = selectedFlow()) => {
		actionLinks.forEach((link) => {
			applyFlowToLink(link, flow);
		});
	};

	flowInputs.forEach((input) => {
		input.addEventListener("change", () => {
			updateCardActions();
		});
	});

	actionLinks.forEach((link) => {
		link.addEventListener("click", () => {
			applyFlowToLink(link, selectedFlow());
		});
	});

	updateCardActions();
})();
