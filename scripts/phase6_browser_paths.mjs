import { chromium, firefox, webkit } from "playwright-core";
import { SCENARIOS, VIEWPORTS, auditAccessibilityAndLayout, captureScreenshot, requireCondition } from "./phase6_browser_common.mjs";
import { assertUiMatchesPayload, isExecuteResponse, readReceiptId, verifyHeaders, verifyMissingReceipt, verifyReceiptLookup, verifySourceModeIndicator } from "./phase6_browser_assertions.mjs";

const BROWSERS = Object.freeze([["chromium", chromium], ["firefox", firefox], ["webkit", webkit]]);

async function runProductionCell(browserName, browserType, viewport, options, shared) {
  const startedAt = Date.now();
  const browser = await browserType.launch({ headless: true });
  const browserVersion = browser.version();
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    deviceScaleFactor: viewport.deviceScaleFactor,
    colorScheme: "dark",
    locale: "en-US",
  });
  const page = await context.newPage();
  page.setDefaultTimeout(25_000);
  const consoleErrors = [];
  const pageErrors = [];
  const failedRequests = [];
  page.on("console", (message) => message.type() === "error" && consoleErrors.push(message.text()));
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  page.on("requestfailed", (request) => failedRequests.push({ url: request.url(), failure: request.failure()?.errorText ?? "unknown" }));

  const defaultResponsePromise = page.waitForResponse(isExecuteResponse, { timeout: 30_000 });
  const navigationResponse = await page.goto(options.origin, { waitUntil: "domcontentloaded", timeout: 30_000 });
  requireCondition(navigationResponse?.status() === 200, `${browserName}/${viewport.name}: document load failed`);
  const documentHeaders = verifyHeaders(navigationResponse.headers(), "document");

  const readyResponse = await context.request.get(`${options.origin}/api/ready`);
  requireCondition(readyResponse.status() === 200, `${browserName}/${viewport.name}: readiness status ${readyResponse.status()}`);
  const apiHeaders = verifyHeaders(readyResponse.headers(), "api");
  const readyPayload = await readyResponse.json();
  requireCondition(readyPayload.status === "ok" && readyPayload.mode === "fixture", "production E2E readiness drift");
  requireCondition(readyPayload.database_ready === true && readyPayload.receipt_store_ready === true, "production state not ready");
  const sourceModeIndicator = await verifySourceModeIndicator(
    page,
    "Fixture execution",
    viewport.width > 900,
  );
  requireCondition((await page.locator(".mode-notice").count()) === 0, "unexpected replay notice on API path");

  const scenarioResults = [];
  const defaultResponse = await defaultResponsePromise;
  requireCondition(defaultResponse.status() === 200, `default execute-safe status ${defaultResponse.status()}`);
  const defaultPayload = await defaultResponse.json();
  await assertUiMatchesPayload(page, defaultPayload, SCENARIOS[0]);
  scenarioResults.push({
    scenario_id: SCENARIOS[0].id,
    initial_decision: defaultPayload.initial_decision.decision,
    effective_decision: defaultPayload.effective_decision,
    receipt: await verifyReceiptLookup(context, options.origin, defaultPayload),
    screenshot: await captureScreenshot(page, options.outputDir, `${browserName}-${viewport.name}-rewrite.png`),
  });

  for (const scenario of SCENARIOS.slice(1)) {
    const responsePromise = page.waitForResponse(isExecuteResponse, { timeout: 30_000 });
    await page.getByRole("button", { name: new RegExp(scenario.title, "i") }).click();
    const response = await responsePromise;
    requireCondition(response.status() === 200, `${scenario.id}: execute-safe status ${response.status()}`);
    const payload = await response.json();
    await assertUiMatchesPayload(page, payload, scenario);
    scenarioResults.push({
      scenario_id: scenario.id,
      initial_decision: payload.initial_decision.decision,
      effective_decision: payload.effective_decision,
      receipt: await verifyReceiptLookup(context, options.origin, payload),
      screenshot: await captureScreenshot(page, options.outputDir, `${browserName}-${viewport.name}-${scenario.initial.toLowerCase()}.png`),
    });
  }

  const accessibilityAndLayout = await auditAccessibilityAndLayout(page, viewport);
  requireCondition(consoleErrors.length === 0, `${browserName}/${viewport.name}: console errors: ${consoleErrors.join(" | ")}`);
  requireCondition(pageErrors.length === 0, `${browserName}/${viewport.name}: page errors: ${pageErrors.join(" | ")}`);
  requireCondition(failedRequests.length === 0, `${browserName}/${viewport.name}: failed requests detected`);
  if (!shared.missingReceipt) shared.missingReceipt = await verifyMissingReceipt(context, options.origin);
  if (!shared.securityHeaders) shared.securityHeaders = { document: documentHeaders, api: apiHeaders, hsts_applicable: options.origin.startsWith("https://") };
  await context.close();
  await browser.close();
  return {
    browser: browserName,
    browser_version: browserVersion,
    viewport: { name: viewport.name, width: viewport.width, height: viewport.height, device_scale_factor: viewport.deviceScaleFactor },
    source_mode: "api",
    source_mode_indicator: sourceModeIndicator,
    readiness: {
      status: readyPayload.status,
      mode: readyPayload.mode,
      policy_version: readyPayload.policy_version,
      database_ready: readyPayload.database_ready,
      receipt_store_ready: readyPayload.receipt_store_ready,
      governance_ready: readyPayload.governance_ready,
    },
    scenarios: scenarioResults,
    accessibility_and_layout: accessibilityAndLayout,
    console_errors: consoleErrors,
    page_errors: pageErrors,
    failed_requests: failedRequests,
    duration_ms: Date.now() - startedAt,
  };
}

export async function runBrowserMatrix(options, shared) {
  const matrix = [];
  for (const [browserName, browserType] of BROWSERS) {
    for (const viewport of VIEWPORTS) matrix.push(await runProductionCell(browserName, browserType, viewport, options, shared));
  }
  return matrix;
}

export async function runFailureDisclosure(options) {
  const browser = await chromium.launch({ headless: true });
  const browserVersion = browser.version();
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: "dark", locale: "en-US" });
  const page = await context.newPage();
  let intercepted = 0;
  await page.route("**/api/execute-safe", async (route) => {
    intercepted += 1;
    await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: { code: "PIPELINE_NOT_READY" } }) });
  });
  await page.goto(options.origin, { waitUntil: "domcontentloaded" });
  const alert = page.getByRole("alert");
  await alert.waitFor({ state: "visible", timeout: 30_000 });
  const text = (await alert.textContent())?.replace(/\s+/g, " ").trim() ?? "";
  requireCondition(text.includes("Protected execution did not complete") && text.includes("Request failed: 503"), "failure disclosure drift");
  const sourceModeIndicator = await verifySourceModeIndicator(page, "Fixture execution", true);
  requireCondition((await page.locator(".mode-notice").count()) === 0, "failure disclosure incorrectly claimed replay");
  requireCondition(intercepted === 1, `expected one intercepted execute request, got ${intercepted}`);
  const screenshot = await captureScreenshot(page, options.outputDir, "negative-failure-disclosure.png");
  await context.close();
  await browser.close();
  return { browser: "chromium", browser_version: browserVersion, source_mode: "api", source_mode_indicator: sourceModeIndicator, intercepted_execute_requests: intercepted, alert_text: text, retry_control_present: true, screenshot };
}

export async function runReplayTruthfulness(options) {
  const browser = await chromium.launch({ headless: true });
  const browserVersion = browser.version();
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, colorScheme: "dark", locale: "en-US" });
  const page = await context.newPage();
  let executeSafeRequests = 0;
  let bootstrapRequests = 0;
  await page.route("**/api/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === "/api/execute-safe") executeSafeRequests += 1;
    else bootstrapRequests += 1;
    await route.abort("failed");
  });
  await page.goto(options.origin, { waitUntil: "domcontentloaded" });
  const sourceModeIndicator = await verifySourceModeIndicator(
    page,
    "Historical deterministic replay",
    false,
  );
  const notice = page.locator(".mode-notice");
  await notice.waitFor({ state: "visible" });
  const noticeText = (await notice.textContent())?.replace(/\s+/g, " ").trim() ?? "";
  requireCondition(noticeText.includes("clearly labeled deterministic replay"), "replay notice lacks truthful label");
  requireCondition(noticeText.includes("no live execution or DataHub write is being claimed"), "replay notice overclaims live behavior");
  await page.getByText("Replay — no live write claimed", { exact: true }).waitFor({ timeout: 30_000 });
  const receiptId = await readReceiptId(page);
  requireCondition(receiptId !== null, "replay did not render deterministic receipt");
  requireCondition(executeSafeRequests === 0 && bootstrapRequests >= 1, "replay network boundary failed");
  const accessibilityAndLayout = await auditAccessibilityAndLayout(page, VIEWPORTS[1]);
  const screenshot = await captureScreenshot(page, options.outputDir, "negative-replay-truthful-mobile.png");
  await context.close();
  await browser.close();
  return {
    browser: "chromium",
    browser_version: browserVersion,
    viewport: VIEWPORTS[1],
    source_mode: "replay",
    source_mode_indicator: sourceModeIndicator,
    bootstrap_requests_failed: bootstrapRequests,
    execute_safe_requests: executeSafeRequests,
    notice_text: noticeText,
    receipt_id: receiptId,
    no_live_write_claimed: true,
    accessibility_and_layout: accessibilityAndLayout,
    screenshot,
  };
}
