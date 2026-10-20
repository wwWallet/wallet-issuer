import eslint from '@eslint/js';
import { defineConfig } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import prettierConfig from 'eslint-config-prettier/flat';

const typescriptFiles = ['{cmd,config,src}/**/*.ts', '*.config.ts', 'setup-vitest.ts'];
const browserFiles = ['public/js/**/*.js'];

export default defineConfig(
	{
		ignores: ['build/**', 'dist/**', 'node_modules/**', 'public/js/qr.min.js'],
	},
	{
		linterOptions: {
			reportUnusedDisableDirectives: 'error',
		},
	},
	eslint.configs.recommended,
	...tseslint.configs.recommended,
	{
		files: typescriptFiles,
		languageOptions: {
			globals: {
				...globals.node,
				...globals.vitest,
			},
		},
		rules: {
			'@typescript-eslint/no-explicit-any': 'off',
			// Remove require()
			'@typescript-eslint/no-require-imports': 'off',
			'@typescript-eslint/no-unused-vars': [
				'error',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
				},
			],
			'no-undef': 'off',
		},
	},
	{
		files: browserFiles,
		languageOptions: {
			globals: {
				...globals.browser,
				QRCode: 'readonly',
			},
		},
	},
	prettierConfig,
);
