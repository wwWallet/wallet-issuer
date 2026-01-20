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
			'no-undef': "off",
			'@typescript-eslint/no-unused-vars': 'off',
		},
	},
	{
		ignores: ['dist/', 'node_modules/', 'build/'],
	},

	prettierConfig,
);
