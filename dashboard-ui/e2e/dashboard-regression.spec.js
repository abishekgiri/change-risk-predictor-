const { test, expect } = require("@playwright/test");

function isoHoursAgo(hoursAgo) {
  const now = new Date();
  return new Date(now.getTime() - hoursAgo * 60 * 60 * 1000).toISOString();
}

test("tenant and date scope persist across dashboard navigation", async ({ page }) => {
  const tenantId = "scope-e2e";
  const fromTs = isoHoursAgo(24);
  const toTs = new Date().toISOString();
  const encodedFrom = encodeURIComponent(fromTs);
  const encodedTo = encodeURIComponent(toTs);

  await page.goto(`/overview?tenant_id=${tenantId}&from=${encodedFrom}&to=${encodedTo}`);

  await page.getByRole("link", { name: "Integrity" }).click();
  await expect(page).toHaveURL(new RegExp(`\\/integrity\\?(.+&)?tenant_id=${tenantId}`));
  await expect(page).toHaveURL(new RegExp(`from=${encodedFrom}`));
  await expect(page).toHaveURL(new RegExp(`to=${encodedTo}`));

  await page.getByRole("link", { name: "Overrides" }).click();
  await expect(page).toHaveURL(new RegExp(`\\/overrides\\?(.+&)?tenant_id=${tenantId}`));
  await expect(page).toHaveURL(new RegExp(`from=${encodedFrom}`));
  await expect(page).toHaveURL(new RegExp(`to=${encodedTo}`));
});

test("integrity page shows empty state for tenant with no rollups", async ({ page }) => {
  const tenantId = `empty-e2e-${Date.now()}`;
  await page.goto(`/integrity?tenant_id=${tenantId}`);
  await expect(page.getByText("No integrity data yet")).toBeVisible();
});

test("integrity single-point rendering remains stable when available", async ({ page }) => {
  await page.goto("/integrity?tenant_id=local");
  const singlePointTitle = page.getByText("Integrity / Drift / Override Rate (single point)");
  const count = await singlePointTitle.count();
  test.skip(count === 0, "Single-point scenario not present for current tenant data.");
  await expect(singlePointTitle.first()).toBeVisible();
  const circleCount = await page.locator("svg circle").count();
  expect(circleCount).toBeGreaterThan(0);
});

test("overrides page renders table or empty state without crashing", async ({ page }) => {
  await page.goto("/overrides?tenant_id=local");
  const table = page.locator("table");
  const empty = page.getByText("No override events in this range");
  const tableCount = await table.count();
  const emptyCount = await empty.count();
  expect(tableCount + emptyCount).toBeGreaterThan(0);
});
