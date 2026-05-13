import tseslint from 'typescript-eslint';
import obsidianmd from "eslint-plugin-obsidianmd";
import globals from "globals";

export default tseslint.config(
	{
		ignores: [
			"node_modules/**",
			"dist/**",
			"esbuild.config.mjs",
			"eslint.config.mts",
			"package-lock.json",
			"package.json",
			"version-bump.mjs",
			"versions.json",
			"main.js",
		],
	},

	...tseslint.configs.recommended,
	...obsidianmd.configs.recommended,
	
	{
		files: ["src/**/*.ts"],
		languageOptions: {
			globals: {
				...globals.browser,
				...globals.node,
			},
			parser: tseslint.parser,
			parserOptions: {
				project: true,
				tsconfigRootDir: import.meta.dirname,
				sourceType: "module",
			},
		},
		rules: {
            "@typescript-eslint/no-this-alias": "off"
		}
	}
);
