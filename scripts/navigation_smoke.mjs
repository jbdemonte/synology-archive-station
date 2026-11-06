import assert from "node:assert/strict";
import { chromium } from "playwright";

const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.CHROMIUM_PATH || undefined,
});
const page = await browser.newPage({
  locale: "fr-FR",
  viewport: { width: 1000, height: 580 },
});
const base = process.env.TEST_URL || "http://127.0.0.1:8275";
const errors = [];
page.on("pageerror", (error) => errors.push(error.message));
const job = {
  id: "navigation",
  identifier: "navigation-archive",
  title: "Navigation archive",
  status: "paused",
  file_count: 300,
  completed_files: 150,
  failed_files: 150,
  total_size: 3000,
  downloaded: 1500,
  destination: "/volume1/Archives",
};
async function retainsFocus(selector, key) {
  const target = page.locator(selector);
  await target.focus();
  if (key) await target.press(key);
  assert.ok(
    await target.evaluate((el) => el === document.activeElement),
    `${selector}: focus survives keyboard activation`,
  );
  const previous = await target.elementHandle();
  await page.waitForFunction((el) => !el.isConnected, previous);
  assert.ok(
    await target.evaluate((el) => el === document.activeElement),
    `${selector}: focus survives polling`,
  );
}
async function paginate(prefix) {
  for (const [label, index] of [
    ["Suivants →", 100],
    ["← Précédents", 0],
  ]) {
    await page
      .locator(`[data-page="navigation"][data-prefix="${prefix}"]`)
      .filter({ hasText: label })
      .click();
    const first = page.locator(
      `.child-row[data-file-path="${prefix}file-${String(index).padStart(3, "0")}.zip"]`,
    );
    await first.waitFor();
    // Bounding boxes, rather than Playwright's auto-scrolling clicks, prove
    // the first row is visible below the sticky table header after pagination.
    await page.waitForFunction(
      (path) => {
        const row = [...document.querySelectorAll("[data-file-path]")].find(
          (el) => el.dataset.filePath === path,
        );
        if (!row) return false;
        const box = row.getBoundingClientRect();
        const header = document
          .querySelector(".downloads th")
          .getBoundingClientRect();
        const viewport = document
          .querySelector(".table-scroll")
          .getBoundingClientRect();
        return box.top >= header.bottom - 1 && box.bottom <= viewport.bottom;
      },
      `${prefix}file-${String(index).padStart(3, "0")}.zip`,
      { timeout: 3000 },
    );
  }
}
try {
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    let body;
    if (url.pathname === "/api/auth")
      body = { authenticated: true, mode: "local" };
    else if (url.pathname === "/api/settings")
      body = {
        language: "fr",
        download_dir: job.destination,
        connections: 5,
        version: "test",
      };
    else if (url.pathname === "/api/jobs") body = { jobs: [job] };
    else if (url.pathname.endsWith("/activity"))
      body = {
        active: [],
        queued: [],
        errors: [],
        counts: { downloading: 0, queued: 0, error: 0 },
      };
    else if (/\/(tree|files)$/.test(url.pathname)) {
      const prefix = url.searchParams.get("prefix") || "";
      const offset = Number(url.searchParams.get("offset") || 0);
      const status = url.searchParams.get("status") || "queued";
      const rows = Array.from({ length: 150 }, (_, i) => ({
        id: i + 1,
        kind: "file",
        name: `${prefix}file-${String(i).padStart(3, "0")}.zip`,
        path: `${prefix}file-${String(i).padStart(3, "0")}.zip`,
        size: 10,
        downloaded: status === "completed" ? 10 : 0,
        status,
      }));
      if (url.pathname.endsWith("/tree") && !prefix)
        rows.push({
          kind: "folder",
          name: "nested",
          path: "nested/",
          size: 1500,
          downloaded: 0,
          status: "queued",
          file_count: 150,
          completed_files: 0,
        });
      body = {
        total: rows.length,
        offset,
        [url.pathname.endsWith("/tree") ? "children" : "files"]: rows.slice(
          offset,
          offset + 100,
        ),
      };
    } else throw new Error(url.pathname);
    await route.fulfill({ json: body });
  });
  await page.goto(base);
  await page.locator(".job-row").waitFor();
  await retainsFocus(".job-row", "Enter");
  await retainsFocus(".job-row .job-check", "Space");
  await retainsFocus(".job-row [data-expand]", "Enter");
  await retainsFocus(".job-row [data-expand]", "Enter");
  await page.locator(".job-row [data-expand]").press("Enter");
  for (const view of ["tree", "completed", "error"]) {
    await page.locator(`[data-file-view="${view}"]`).click();
    await page.locator('.child-row[data-file-path="file-000.zip"]').waitFor();
    await paginate("");
  }
  await page.locator('[data-file-view="tree"]').click();
  await page
    .locator('[data-page][data-prefix=""]')
    .filter({ hasText: "Suivants →" })
    .click();
  await page.locator('[data-expand][data-prefix="nested/"]').click();
  await page
    .locator('.child-row[data-file-path="nested/file-000.zip"]')
    .waitFor();
  await retainsFocus('[data-expand][data-prefix="nested/"]');
  await paginate("nested/");
  // Polling must also leave focus alone when it is outside the task list.
  await page.locator("#search").focus();
  const previous = await page.locator(".job-row").elementHandle();
  await page.waitForFunction((el) => !el.isConnected, previous);
  assert.ok(
    await page
      .locator("#search")
      .evaluate((el) => el === document.activeElement),
  );
  assert.deepEqual(errors, []);
  console.log(
    "Navigation passed: root/nested tree and completed/error pagination, keyboard activation and focus across polling.",
  );
} finally {
  await browser.close();
}
