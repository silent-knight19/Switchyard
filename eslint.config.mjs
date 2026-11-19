import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/node_modules/**', 'docs/**', '.agents/**', 'pnpm-lock.yaml'],
  },
  ...tseslint.configs.recommended,
);
