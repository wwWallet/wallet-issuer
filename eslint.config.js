import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettierConfig from 'eslint-config-prettier/flat';

export default tseslint.config(
	eslint.configs.recommended,

	...tseslint.configs.recommended,

	{
		rules: {
			'@typescript-eslint/no-explicit-any': 'off',
			'no-undef': 'off',
			'@typescript-eslint/no-unused-vars': 'off',
		},
	},
	{
		ignores: ['dist/', 'node_modules/', 'build/', 'public/js/qr.min.js'],
	},

	prettierConfig,
);
