import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import ts from 'typescript';
import { afterEach, describe, expect, it } from 'vitest';

const directories: string[] = [];

afterEach(() => {
	for (const directory of directories.splice(0)) {
		rmSync(directory, { recursive: true, force: true });
	}
});

describe('locale configuration', () => {
	const loadLocale = (localSource?: string) => {
		const directory = mkdtempSync(join(tmpdir(), 'issuer-locale-'));
		directories.push(directory);
		const source = readFileSync(join(process.cwd(), 'config/locale.ts'), 'utf8');
		const compiled = ts.transpileModule(source, {
			compilerOptions: { module: ts.ModuleKind.CommonJS },
		}).outputText;
		const modulePath = join(directory, 'locale.js');
		writeFileSync(modulePath, compiled);
		if (localSource) writeFileSync(join(directory, 'locale.local.js'), localSource);
		return createRequire(modulePath)(modulePath).locale as typeof import('./locale').locale;
	};

	it('merges named local overrides while retaining unspecified defaults', () => {
		const locale = loadLocale("exports.locale = { about: { intro: 'Local introduction' } };");
		expect(locale.about.intro).toBe('Local introduction');
		expect(locale.about.subtitle).toBe('About this service');
		expect(locale.nav.home).toBe('Home');
	});

	it('uses defaults when no local configuration exists', () => {
		expect(loadLocale().about.intro).toContain('The Demo wwWallet Issuer');
	});

	it('uses defaults when the local module has no locale object', () => {
		for (const source of [
			'module.exports = {};',
			'exports.locale = null;',
			'exports.locale = [];',
		]) {
			expect(loadLocale(source).about.intro).toContain('The Demo wwWallet Issuer');
		}
	});

	it('does not hide missing dependencies of the local module', () => {
		expect(() => loadLocale("require('./missing-dependency');")).toThrow('missing-dependency');
	});
});
