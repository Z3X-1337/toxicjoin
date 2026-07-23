import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright-core";

const uiUrl = process.env.DATAHUB_UI_URL ?? "http://127.0.0.1:9002";
const username = process.env.DATAHUB_UI_USERNAME ?? "datahub";
const password = process.env.DATAHUB_UI_PASSWORD ?? "datahub";
const browserExecutable = process.env.BROWSER_EXECUTABLE;
const outputDir = process.env.DATAHUB_CAPTURE_DIR ?? ".toxicjoin/video-captures";

if (!browserExecutable || !fs.existsSync(browserExecutable)) {
  throw new Error(`BROWSER_EXECUTABLE is missing or invalid: ${browserExecutable ?? "unset"}`);
}

fs.mkdirSync(outputDir, { recursive: true });

const browser = await chromium.launch({
  headless: true,
  executablePath: browserExecutable,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

const context = await browser.newContext({
  viewport: { width: 1600, height: 1000 },
  deviceScaleFactor: 1,
  reducedMotion: "reduce",
});
const page = await context.newPage();
const consoleErrors = [];
const pageErrors = [];

page.on("console", (message) => {
  if (message.type() === "error") consoleErrors.push(message.text());
});
page.on("pageerror", (error) => pageErrors.push(String(error)));

const captures = [];

async function settle() {
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(1200);
}

async function screenshot(name, evidence = []) {
  const target = path.join(outputDir, `${name}.png`);
  const bodyText = (await page.locator("body").innerText()).replace(/\s+/g, " ").trim();
  for (const required of evidence) {
    if (!bodyText.toLowerCase().includes(required.toLowerCase())) {
      throw new Error(`${name}: required visible evidence not found: ${required}`);
    }
  }
  await page.screenshot({ path: target, fullPage: true });
  const stats = fs.statSync(target);
  if (stats.size < 20_000) {
    throw new Error(`${name}: screenshot is unexpectedly small (${stats.size} bytes)`);
  }
  captures.push({
    name,
    file: target,
    bytes: stats.size,
    url: page.url(),
    evidence,
  });
}

async function persistFailureDiagnostics(error) {
  const diagnostics = {
    schema_version: "1.0",
    status: "failed",
    error_name: error?.name ?? "Error",
    error_message: String(error?.message ?? error),
    url: page.url(),
    title: await page.title().catch(() => ""),
    console_errors: consoleErrors,
    page_errors: pageErrors,
    captures_completed: captures,
  };

  try {
    const text = (await page.locator("body").innerText()).replace(/\s+/g, " ").trim();
    diagnostics.visible_text = text.slice(0, 12000);
  } catch {
    diagnostics.visible_text = "";
  }

  fs.writeFileSync(
    path.join(outputDir, "failure.json"),
    `${JSON.stringify(diagnostics, null, 2)}\n`,
    "utf8",
  );

  try {
    fs.writeFileSync(path.join(outputDir, "failure.html"), await page.content(), "utf8");
  } catch {
    // The JSON report remains authoritative even if the DOM is no longer available.
  }

  try {
    await page.screenshot({ path: path.join(outputDir, "failure.png"), fullPage: true });
  } catch {
    // Preserve the original capture error rather than replacing it with a screenshot error.
  }
}

async function loginIfNeeded() {
  // Match DataHub's own Playwright/Cypress login contract exactly. Avoid any
  // role/text fallback because the adjacent SSO button is intentionally not
  // valid in the local quickstart used for capture evidence.
  await page.addInitScript(() => {
    localStorage.setItem("skipWelcomeModal", "true");
  });

  await page.goto(uiUrl, { waitUntil: "domcontentloaded", timeout: 60_000 });
  await settle();

  if (!new URL(page.url()).pathname.includes("/login")) {
    return;
  }

  const usernameInput = page.locator('input[data-testid="username"]').first();
  const passwordInput = page.locator('input[data-testid="password"]').first();
  const signInButton = page.locator('[data-testid="sign-in"]').first();

  if ((await usernameInput.count()) === 0 || !(await usernameInput.isVisible())) {
    throw new Error("DataHub login page did not expose the official username field");
  }
  if ((await passwordInput.count()) === 0 || !(await passwordInput.isVisible())) {
    throw new Error("DataHub login page did not expose the official password field");
  }
  if ((await signInButton.count()) === 0 || !(await signInButton.isVisible())) {
    throw new Error("DataHub login page did not expose the official sign-in control");
  }

  await usernameInput.fill(username);
  await passwordInput.fill(password);

  if ((await usernameInput.inputValue()) !== username) {
    throw new Error("DataHub username field did not retain the configured credential");
  }
  if ((await passwordInput.inputValue()) !== password) {
    throw new Error("DataHub password field did not retain the configured credential");
  }

  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (await signInButton.isEnabled()) break;
    await page.waitForTimeout(100);
  }
  if (!(await signInButton.isEnabled())) {
    throw new Error("DataHub sign-in control remained disabled after credentials were filled");
  }

  await signInButton.click();
  await page.waitForURL((url) => !url.pathname.includes("/login"), {
    waitUntil: "domcontentloaded",
    timeout: 30_000,
  });
  await settle();

  if (page.url().includes("error_msg=SSO")) {
    throw new Error("Capture flow entered DataHub SSO instead of password login");
  }
}

async function findSearchBox() {
  const candidates = [
    page.locator('input[placeholder*="Search" i]'),
    page.getByRole("textbox", { name: /search/i }),
    page.locator('input[type="search"]'),
  ];
  for (const locator of candidates) {
    const count = await locator.count();
    for (let i = 0; i < count; i += 1) {
      const candidate = locator.nth(i);
      if (await candidate.isVisible()) return candidate;
    }
  }
  throw new Error(`No visible DataHub search box found at ${page.url()}`);
}

async function searchAndOpen(query, visibleLabel) {
  await page.goto(uiUrl, { waitUntil: "domcontentloaded", timeout: 60_000 });
  await settle();
  const search = await findSearchBox();
  await search.fill(query);
  await search.press("Enter");
  await page.waitForTimeout(1800);

  const result = page.getByText(visibleLabel, { exact: false }).first();
  if ((await result.count()) === 0 || !(await result.isVisible())) {
    await screenshot(`diagnostic-search-${query.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`);
    throw new Error(`Search result not found for ${query}: expected visible label ${visibleLabel}`);
  }
  await result.click();
  await settle();
}

try {
  await loginIfNeeded();
  await screenshot("01-datahub-home", ["DataHub"]);

  await searchAndOpen("retention_scores", "retention_scores");
  await screenshot("02-retention-scores-overview", ["retention_scores", "churn_score"]);

  const lineageControl = page.getByText("Lineage", { exact: true }).first();
  if ((await lineageControl.count()) === 0 || !(await lineageControl.isVisible())) {
    throw new Error("retention_scores page does not expose a visible Lineage control");
  }
  await lineageControl.click();
  await page.waitForTimeout(1600);
  await screenshot("03-retention-scores-lineage", ["retention_scores", "Lineage"]);

  await searchAndOpen("Compositional Risk Review", "Compositional Risk Review");
  await screenshot("04-compositional-risk-agent-skill", ["Compositional Risk Review"]);

  await searchAndOpen("ToxicJoin Privacy Firewall Agent", "ToxicJoin Privacy Firewall Agent");
  await screenshot("05-toxicjoin-ai-agent", ["ToxicJoin Privacy Firewall Agent"]);

  if (consoleErrors.length) {
    throw new Error(`DataHub UI console errors: ${consoleErrors.join(" | ")}`);
  }
  if (pageErrors.length) {
    throw new Error(`DataHub UI page errors: ${pageErrors.join(" | ")}`);
  }

  const manifest = {
    schema_version: "1.0",
    source: "real-datahub-oss-ui",
    ui_url_origin: new URL(uiUrl).origin,
    viewport: { width: 1600, height: 1000 },
    capture_count: captures.length,
    captures,
    console_error_count: 0,
    page_error_count: 0,
  };
  fs.writeFileSync(
    path.join(outputDir, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
  console.log(JSON.stringify(manifest, null, 2));
} catch (error) {
  await persistFailureDiagnostics(error);
  throw error;
} finally {
  await browser.close();
}
