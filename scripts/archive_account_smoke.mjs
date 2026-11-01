import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { chromium } from "playwright";

const base = process.env.TEST_URL || "http://127.0.0.1:8275";
const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.CHROMIUM_PATH || undefined,
});
const page = await browser.newPage({
  viewport: { width: 1080, height: 760 },
  locale: "en-US",
});
const errors = [];
page.on("pageerror", (error) => errors.push(error.message));
let account = { connected: false, state: "disconnected", email: "" };
let loginRelease;
let loginRequests = 0;
let rejectLogin = true;
const password = "fixture-never-persist-this-password";
try {
  await page.route(`${base}/api/settings`, async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    const response = await route.fetch();
    const settings = await response.json();
    return route.fulfill({
      json: { ...settings, language: "en", archive_account: account },
    });
  });
  await page.route(`${base}/api/inspect`, (route) =>
    route.fulfill({
      json: {
        identifier: "restricted-demo",
        title: "Restricted example",
        file_count: account.connected ? 61 : 5,
        private_files: account.connected ? 0 : 56,
        restricted_files: account.connected ? 56 : 0,
        total_size: 4096,
        unknown_sizes: 0,
        sample: ["readme.txt"],
        plan_id: "fixture-plan",
      },
    }),
  );
  await page.route(`${base}/api/archive-account/login`, async (route) => {
    loginRequests++;
    assert.deepEqual(route.request().postDataJSON(), {
      email: "reader@example.test",
      password,
    });
    assert.equal(route.request().url().includes(password), false);
    await new Promise((resolve) => {
      loginRelease = resolve;
    });
    if (rejectLogin)
      return route.fulfill({
        status: 400,
        json: {
          error:
            "Connexion Internet Archive refusée. Vérifier les identifiants et les autorisations du compte.",
        },
      });
    account = {
      connected: true,
      state: "connected",
      email: "reader@example.test",
    };
    return route.fulfill({ json: account });
  });
  await page.route(`${base}/api/archive-account/logout`, (route) => {
    account = { connected: false, state: "disconnected", email: "" };
    return route.fulfill({ json: account });
  });
  await page.goto(base);
  await page.locator("#application").waitFor({ state: "visible" });
  await page.locator("#add-open").click();
  await page
    .locator("#urls")
    .fill("https://archive.org/details/restricted-demo");
  await page.locator("#inspect-button").click();
  await page.locator(".restricted-notice").waitFor();
  assert.match(
    await page.locator(".restricted-notice").innerText(),
    /excluded: 56.*Settings/,
  );
  await page.locator('#add-dialog [data-close="add-dialog"]').last().click();
  await page.locator("#settings-open").click();
  await page.locator("#settings-dialog").waitFor();
  assert.equal(
    await page.locator("#archive-account-status").innerText(),
    "Public access only.",
  );
  await page.locator("#archive-account-open").click();
  await page.locator("#archive-account-email").fill("reader@example.test");
  await page.locator("#archive-account-password").fill(password);
  await page.locator("#archive-account-submit").click();
  await page.waitForFunction(
    () =>
      document
        .querySelector("#archive-account-form")
        .getAttribute("aria-busy") === "true",
  );
  assert.equal(
    await page.locator("#archive-account-password").isDisabled(),
    true,
  );
  assert.equal(await page.locator("#archive-account-email").isDisabled(), true);
  assert.equal(
    await page.locator("#archive-account-progress").isVisible(),
    true,
  );
  await page.keyboard.press("Escape");
  assert.equal(await page.locator("#archive-account-dialog").isVisible(), true);
  while (!loginRelease) await new Promise((resolve) => setTimeout(resolve, 10));
  loginRelease();
  await page
    .locator("#archive-account-error")
    .getByText(/sign-in refused/)
    .waitFor();
  assert.equal(
    await page.locator("#archive-account-password").inputValue(),
    "",
  );
  assert.equal(await page.locator("#login-screen").isVisible(), false);
  rejectLogin = false;
  loginRelease = null;
  await page.locator("#archive-account-password").fill(password);
  await page.locator("#archive-account-submit").click();
  while (!loginRelease) await new Promise((resolve) => setTimeout(resolve, 10));
  loginRelease();
  await page.locator("#archive-account-dialog").waitFor({ state: "hidden" });
  assert.match(
    await page.locator("#archive-account-status").innerText(),
    /reader@example.test/,
  );
  assert.equal(
    await page.locator("#archive-account-password").inputValue(),
    "",
  );
  assert.equal(
    await page.evaluate(
      (secret) => JSON.stringify(localStorage).includes(secret),
      password,
    ),
    false,
  );
  assert.equal(loginRequests, 2);
  // Capture a clean demonstration, with no password in the DOM or screenshot.
  await page.locator("#archive-account-open").click();
  await mkdir(".local/archive-account", { recursive: true });
  await page.screenshot({ path: ".local/archive-account/dialog.png" });
  await page.setViewportSize({ width: 800, height: 460 });
  const footer = await page.locator("#archive-account-submit").boundingBox();
  assert.ok(footer.y >= 0 && footer.y + footer.height <= 460);
  await page
    .locator('#archive-account-dialog [data-close="archive-account-dialog"]')
    .last()
    .click();
  await page.setViewportSize({ width: 1080, height: 760 });
  await page
    .locator('#settings-dialog [data-close="settings-dialog"]')
    .last()
    .click();
  await page.locator("#add-open").click();
  await page.locator("#inspect-button").click();
  await page.locator(".restricted-notice").waitFor();
  assert.match(
    await page.locator(".restricted-notice").innerText(),
    /included: 56.*checked/,
  );
  await page.locator('#add-dialog [data-close="add-dialog"]').last().click();
  await page.locator("#settings-open").click();
  await page.locator("#archive-account-disconnect").click();
  await page
    .locator("#archive-account-status")
    .getByText("Public access only.")
    .waitFor();
  assert.equal(
    await page.locator("#archive-account-disconnect").isVisible(),
    false,
  );
  assert.deepEqual(errors, []);
  console.log(
    "Internet Archive account UI: restricted-file warnings, login loader, safe errors, session controls and compact layout passed.",
  );
} finally {
  loginRelease?.();
  await browser.close();
}
