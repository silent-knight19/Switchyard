import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/.next/**',
      'docs/**',
      '.agents/**',
      'pnpm-lock.yaml',
    ],
  },
  ...tseslint.configs.recommended,
);
