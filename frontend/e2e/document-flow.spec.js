import { expect, test } from '@playwright/test';


const ADMIN_ID = process.env.E2E_ADMIN_ID || 'e2e-admin';
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD || 'e2e-only-password';
const PDF_BYTES = Buffer.from(
  '%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n' +
  '2 0 obj<</Type/Pages/Count 0/Kids[]>>endobj\n' +
  'trailer<</Root 1 0 R>>\n%%EOF\n',
);


async function signIn(page) {
  await page.goto('/admin/login');
  await page.getByLabel('Admin ID').fill(ADMIN_ID);
  await page.getByLabel('Password').fill(ADMIN_PASSWORD);
  await page.getByRole('button', { name: 'Continue to workspace' }).click();
  await expect(page).toHaveURL(/\/register$/);
}


test('registers a PDF and verifies it in the browser', async ({ page }) => {
  await signIn(page);
  await page.getByLabel('Issuer ID (as enrolled)').fill(
    'university-issuing-authority-v1',
  );
  await page.locator('input[type="file"]').setInputFiles({
    name: 'e2e-certificate.pdf',
    mimeType: 'application/pdf',
    buffer: PDF_BYTES,
  });
  await page.getByRole('button', { name: 'Register document' }).click();

  await expect(page).toHaveURL(/\/document\/[0-9a-f-]{36}$/);
  const documentId = page.url().split('/').at(-1);
  await page.goto(`/verify/${documentId}`);
  await page.locator('input[type="file"]').setInputFiles({
    name: 'e2e-certificate.pdf',
    mimeType: 'application/pdf',
    buffer: PDF_BYTES,
  });
  await page.getByRole('button', { name: 'Verify document' }).click();
  await expect(page.locator('.outcome .eyebrow')).toHaveText('VALID');
});


test('reconciles an unresolved registry row and exposes its verification link', async ({ page }) => {
  const documentId = 'c91d774d-08af-4491-85ea-6a1a36cbda14';
  let status = 'LEDGER_FAILED';

  await signIn(page);
  await page.route('**/api/v1/admin/documents?*', async route => {
    const registered = status === 'REGISTERED';
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [{
          document_id: documentId,
          original_filename: 'pending-certificate.pdf',
          issuer: 'Example University',
          document_hash: 'a'.repeat(64),
          signing_algorithm: 'ML-DSA-65',
          kem_algorithm: 'ML-KEM-768',
          status,
          transaction_id: registered ? 'fabric-tx-e2e' : null,
          block_number: registered ? 12 : null,
          created_at: '2026-01-01T00:00:00Z',
          registered_at: registered ? '2026-01-01T00:01:00Z' : null,
          revoked_at: null,
          revocation_reason: null,
          revocation_transaction_id: null,
        }],
        total: 1,
        status_counts: {
          REGISTERED: registered ? 1 : 0,
          LEDGER_FAILED: registered ? 0 : 1,
        },
      }),
    });
  });
  await page.route(
    `**/api/v1/admin/documents/${documentId}/reconcile`,
    async route => {
      status = 'REGISTERED';
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          document_id: documentId,
          status,
          action: 'retry_registered',
          transaction_id: 'fabric-tx-e2e',
          block_number: 12,
        }),
      });
    },
  );

  await page.goto('/registry');
  await expect(page.getByText('LEDGER_FAILED')).toBeVisible();
  await page.getByRole('button', { name: 'Reconcile ledger' }).click();
  await expect(page.getByText(
    'Reconciliation retry registered. Record status: REGISTERED.',
  )).toBeVisible();
  await expect(
    page.getByRole('link', { name: 'Verify record' }),
  ).toHaveAttribute('href', `/verify/${documentId}`);
});
