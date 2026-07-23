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

async function dismissProductTours() {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const closeButton = page
      .locator('#___reactour button.reactour__close, #___reactour button[aria-label="Close"]')
      .first();
    if ((await closeButton.count()) === 0 || !(await closeButton.isVisible())) return;
    await closeButton.click();
    await page.waitForTimeout(300);
  }

  const remaining = page.locator('#___reactour .reactour__helper--is-open').first();
  if ((await remaining.count()) > 0 && (await remaining.isVisible())) {
    throw new Error("DataHub product tour remained open after explicit close attempts");
  }
}

async function settle() {
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(1200);
  await dismissProductTours();
}

async function visibleBodyText() {
  return (await page.locator("body").innerText()).replace(/\s+/g, " ").trim();
}

async function waitForVisibleText(label, timeoutMs = 30_000) {
  const locator = page.getByText(label, { exact: false }).first();
  await locator.waitFor({ state: "visible", timeout: timeoutMs });
  return locator;
}

async function assertCaptureState(name, evidence = []) {
  const bodyText = await visibleBodyText();

  if (/No results found for/i.test(bodyText)) {
    throw new Error(`${name}: refusing to capture a DataHub no-results page`);
  }

  for (const required of evidence) {
    if (!bodyText.toLowerCase().includes(required.toLowerCase())) {
      throw new Error(`${name}: required visible evidence not found: ${required}`);
    }
  }

  const visibleSkeletons = page.locator('.ant-skeleton:visible, [class*="skeleton"]:visible');
  if ((await visibleSkeletons.count()) > 0) {
    throw new Error(`${name}: visible loading skeletons remain in the DataHub UI`);
  }
}

async function screenshot(name, evidence = []) {
  await assertCaptureState(name, evidence);
  const target = path.join(outputDir, `${name}.png`);
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
    capture_mode: "full-page",
  });
}

async function screenshotClip(name, evidence, clip) {
  await assertCaptureState(name, evidence);
  const target = path.join(outputDir, `${name}.png`);
  await page.screenshot({ path: target, clip });
  const stats = fs.statSync(target);
  if (stats.size < 10_000) {
    throw new Error(`${name}: clipped screenshot is unexpectedly small (${stats.size} bytes)`);
  }

  captures.push({
    name,
    file: target,
    bytes: stats.size,
    url: page.url(),
    evidence,
    capture_mode: "fixed-viewport-clip",
    clip,
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
    diagnostics.visible_text = (await visibleBodyText()).slice(0, 12000);
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
  await page.addInitScript(() => {
    localStorage.setItem("skipWelcomeModal", "true");
  });

  await page.goto(uiUrl, { waitUntil: "domcontentloaded", timeout: 60_000 });
  await settle();

  if (!new URL(page.url()).pathname.includes("/login")) return;

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
    page.locator('input[data-testid="search-input"]'),
    page.locator('[data-testid="search-bar"] input'),
    page.locator('input[placeholder^="Find " i]'),
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

async function openRetentionScoresFromSearch() {
  await page.goto(uiUrl, { waitUntil: "domcontentloaded", timeout: 60_000 });
  await settle();

  const search = await findSearchBox();
  await search.fill("retention_scores");
  await search.press("Enter");
  await page.waitForURL((url) => url.pathname.includes("/search"), {
    waitUntil: "domcontentloaded",
    timeout: 15_000,
  });

  const datasetLink = page
    .locator('a[href*="/dataset/"][href*="toxicjoin.retention_scores"]')
    .first();
  await datasetLink.waitFor({ state: "visible", timeout: 30_000 });
  await dismissProductTours();

  await waitForVisibleText("ToxicJoin retention_scores");
  await waitForVisibleText("churn_score");
  await waitForVisibleText("UPSTREAM");
  await waitForVisibleText("Depends on 4 datasets");
  await waitForVisibleText("DOWNSTREAM");
  await waitForVisibleText("Used by 1");

  await screenshot("01-retention-scores-search", [
    "ToxicJoin retention_scores",
    "churn_score",
  ]);

  // The self-hosted UI exposes a fully loaded lineage summary panel on the
  // search result even when the interactive lineage canvas remains skeletal in
  // headless Chromium. Capture the loaded summary rather than presenting a
  // loading canvas as evidence.
  await screenshotClip(
    "03-retention-scores-lineage-summary",
    [
      "ToxicJoin retention_scores",
      "UPSTREAM",
      "Depends on 4 datasets",
      "DOWNSTREAM",
      "Used by 1",
    ],
    { x: 1040, y: 180, width: 495, height: 380 },
  );

  await datasetLink.click();
  await settle();
}

try {
  await loginIfNeeded();

  await openRetentionScoresFromSearch();
  await waitForVisibleText("churn_score");
  await waitForVisibleText("customer_id");
  await waitForVisibleText("model_timestamp");
  await screenshot("02-retention-scores-overview", [
    "ToxicJoin retention_scores",
    "churn_score",
    "customer_id",
    "model_timestamp",
  ]);

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
    lineage_evidence: {
      visual_mode: "loaded-summary-panel",
      upstream_dataset_count: 4,
      downstream_usage_count: 1,
      upstream_names_source: ".toxicjoin/datahub-seed.json and verified MCP/Agent Registry evidence",
      reason:
        "The headless self-hosted lineage canvas remained skeletal while the loaded DataHub summary panel exposed the authoritative dependency counts. The final video uses the real summary panel plus independently verified upstream names instead of a loading graph.",
    },
    agent_registry_evidence: {
      visual_ui_claimed: false,
      reason:
        "Self-hosted OSS does not expose the Cloud Private Beta Agents UI; Agent Registry proof is retained as independently verified machine evidence.",
      registry_report: ".toxicjoin/datahub-agent-registry.json",
      verification_report: ".toxicjoin/datahub-agent-registry-verified.json",
    },
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
