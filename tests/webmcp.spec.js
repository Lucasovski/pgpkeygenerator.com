import { test, expect } from '@playwright/test';

// Simulates a WebMCP-capable browser by stubbing navigator.modelContext
// before app.js runs, then invoking the registered tool's execute().
const installModelContextStub = () => {
    window.__mcpTools = {};
    Object.defineProperty(navigator, 'modelContext', {
        value: {
            registerTool: (tool) => { window.__mcpTools[tool.name] = tool; }
        },
        configurable: true
    });
};

test.describe('WebMCP security hardening', () => {

    test.beforeEach(async ({ page }) => {
        await page.addInitScript(installModelContextStub);
        await page.goto('/');
    });

    test('registers generate_pgp_keys tool', async ({ page }) => {
        const names = await page.evaluate(() => Object.keys(window.__mcpTools));
        expect(names).toContain('generate_pgp_keys');
    });

    test('tool result never leaks private key or revocation certificate', async ({ page }) => {
        const text = await page.evaluate(async () => {
            const res = await window.__mcpTools['generate_pgp_keys'].execute({
                name: 'Alice Smith', email: 'alice@example.com'
            });
            return res.content[0].text;
        });

        expect(text).toContain('-----BEGIN PGP PUBLIC KEY BLOCK-----');
        expect(text).not.toContain('PRIVATE KEY');
        expect(text).not.toContain('Revocation');
        // Private key must still be shown to the human user in the UI.
        await expect(page.locator('#private-key-textarea')).not.toHaveValue('');
    });

    test('rejects missing/invalid arguments without generating', async ({ page }) => {
        const bad1 = await page.evaluate(async () =>
            await window.__mcpTools['generate_pgp_keys'].execute({ name: 'X' }));
        expect(bad1.isError).toBe(true);

        const bad2 = await page.evaluate(async () =>
            await window.__mcpTools['generate_pgp_keys'].execute({ name: 'X', email: 'not-an-email' }));
        expect(bad2.isError).toBe(true);

        await expect(page.locator('#private-key-textarea')).toHaveValue('');
    });

    test('falls back to safe defaults for invalid enum values', async ({ page }) => {
        const text = await page.evaluate(async () => {
            const res = await window.__mcpTools['generate_pgp_keys'].execute({
                name: 'Bob', email: 'bob@example.com',
                type: 'dsa', keySize: 512, expirationTime: 12345
            });
            return res.content[0].text;
        });
        expect(text).toContain('Algorithm: ecc');
    });

    test('passphrase is wiped from the DOM after generation', async ({ page }) => {
        await page.fill('#options-passphrase', 'sup3r-secret');
        await page.fill('#options-name', 'Test User');
        await page.fill('#options-email', 'test@example.com');
        await page.click('#generate-keys-button');
        await expect(page.locator('#private-key-textarea')).not.toHaveValue('', { timeout: 30000 });
        await expect(page.locator('#options-passphrase')).toHaveValue('');
    });

    test('concurrent tool calls are serialized, not cross-resolved', async ({ page }) => {
        const results = await page.evaluate(async () => {
            const [a, b] = await Promise.all([
                window.__mcpTools['generate_pgp_keys'].execute({ name: 'A', email: 'a@example.com' }),
                window.__mcpTools['generate_pgp_keys'].execute({ name: 'B', email: 'b@example.com' })
            ]);
            return [a.content[0].text, b.content[0].text];
        });
        // Both should succeed (serialized), each with its own public key.
        expect(results[0]).toContain('A <a@example.com>');
        expect(results[1]).toContain('B <b@example.com>');
    });
});
