import { createRequire } from 'node:module';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { config } from '../config';

const loadModule = createRequire(__filename);
const pug = loadModule('pug') as {
	renderFile: (path: string, options: Record<string, unknown>) => string;
};

describe('issuer display branding', () => {
	const renderLayout = (pageTitle?: string) =>
		pug.renderFile(path.join(__dirname, 'layout.pug'), {
			displayName: 'Example Issuer',
			displayLogoUri: 'https://issuer.example/logo.svg',
			pageTitle,
			locale: {
				nav: { home: 'Home', about: 'About' },
				footer: { copyrightPrefix: '', copyrightSuffix: '' },
			},
			currentPath: '/',
			csrfToken: 'test-token',
		});

	it('renders the configured site name in the page title and header', () => {
		const html = renderLayout();

		expect(html).toContain('<title>Example Issuer</title>');
		expect(html).toContain('src="https://issuer.example/logo.svg"');
		expect(html).toContain('alt="Example Issuer logo"');
		expect(html).toContain('<span class="brand-title">Example Issuer</span>');
	});

	it('prefixes the configured site name with the page title', () => {
		const html = renderLayout('PID Offer');

		expect(html).toContain('<title>PID Offer | Example Issuer</title>');
	});

	it('uses the issuer display name for the site manifest', () => {
		expect(config.siteConfig.name).toBe(config.display[0].name);
		expect(config.siteConfig.short_name).toBe(config.display[0].name);
	});
});
