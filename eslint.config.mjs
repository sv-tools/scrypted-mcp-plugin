import js from '@eslint/js';
import tseslint from 'typescript-eslint';

// We deliberately don't use `eslint-config-prettier`: typescript-eslint's `recommended`
// preset focuses on code-quality rules, not style. Prettier already owns formatting via
// `npm run fmt` / `fmt:check`, and there's nothing in the rule set below that fights it.
// Skipping the dep also sidesteps the known eslint-config-prettier supply-chain compromise.
export default tseslint.config(
    {
        ignores: ['node_modules/', 'out/', 'build/', 'dist/'],
    },
    js.configs.recommended,
    ...tseslint.configs.recommended,
    {
        rules: {
            // Allow `any` — used intentionally for Scrypted device shapes (untyped JSON
            // varies per device interface) and for narrow casts where TypeScript can't
            // see through runtime-tagged values.
            '@typescript-eslint/no-explicit-any': 'off',

            // Treat `_`-prefixed args/vars as intentionally unused.
            '@typescript-eslint/no-unused-vars': [
                'warn',
                { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
            ],

            // Empty catch blocks are a deliberate teardown idiom: e.g.
            // `try { socket.close(); } catch {}` — best-effort, ignore failure.
            'no-empty': ['warn', { allowEmptyCatch: true }],
        },
    },
);
