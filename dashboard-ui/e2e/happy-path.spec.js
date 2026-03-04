const { test, expect } = require("@playwright/test");

test("overview -> blocked decision -> explainer", async ({ page }) => {
  await page.goto("/overview");

  const table = page.getByTestId("blocked-table");
  await expect(table).toBeVisible();

  const links = page.getByTestId("blocked-row-link");
  const linkCount = await links.count();
  test.skip(linkCount === 0, "No blocked decisions found for this tenant/environment.");

  const firstLink = links.first();
  await expect(firstLink).toBeVisible();
  await firstLink.click();

  await expect(page).toHaveURL(/\/decisions\/.+/);
  await expect(page.getByTestId("snapshot-binding")).toBeVisible();
  await expect(page.getByTestId("decision-outcome")).toBeVisible();
});
