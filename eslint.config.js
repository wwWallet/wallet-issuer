import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettierConfig from 'eslint-config-prettier';
import prettierPlugin from 'eslint-plugin-prettier';

export default tseslint.config(
	eslint.configs.recommended,

	...tseslint.configs.recommended,

	{
		plugins: {
			prettier: prettierPlugin,
		},
		rules: {
			'prettier/prettier': "off",
			'@typescript-eslint/no-explicit-any': 'off',
			'@typescript-eslint/no-unused-vars': [
				'error',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
					caughtErrorsIgnorePattern: '^_',
				},
			],
		},
	},
	{
		ignores: ['dist/', 'node_modules/', 'build/', 'public/'],
	},

	prettierConfig,
);
