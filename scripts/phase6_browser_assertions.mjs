import { RECEIPT_ID_PATTERN, SHA256_PATTERN, requireCondition } from "./phase6_browser_common.mjs";

const POLL_INTERVAL_MS = 100;
const DEFAULT_WAIT_TIMEOUT_MS = 30_000;

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function isExecuteResponse(response) {
  try {
    const url = new URL(response.url());
    return url.pathname === "/api/execute-safe" && response.request().method() === "POST";
  } catch {
    return false;
  }
}

export async function verifySourceModeIndicator(page, expectedText, expectedVisible) {
  const indicator = page.locator('[aria-label="System status"]');
  await indicator.waitFor({ state: "attached", timeout: DEFAULT_WAIT_TIMEOUT_MS });

  const deadline = Date.now() + DEFAULT_WAIT_TIMEOUT_MS;
  let state = null;
  while (Date.now() <= deadline) {
    const text = ((await indicator.textContent()) ?? "").replace(/\s+/g, " ").trim();
    const visible = await indicator.isVisible();
    const box = await indicator.boundingBox();
    state = {
      text,
      visible,
      width: box?.width ?? 0,
      height: box?.height ?? 0,
    };
    if (text.includes(expectedText) && visible === expectedVisible) break;
    await sleep(POLL_INTERVAL_MS);
  }

  requireCondition(state !== null, "source-mode indicator state was not observed");
  requireCondition(state.text.includes(expectedText), `source-mode indicator missing ${expectedText}`);
  requireCondition(state.visible === expectedVisible, `source-mode indicator visibility drift for ${expectedText}`);
  return { ...state, expected_visible: expectedVisible };
}

async function waitForReceipt(page, expectedReceiptId) {
  const locator = page.locator(".receipt-grid > div").filter({ hasText: "Receipt ID" }).locator("dd").first();
  await locator.waitFor({ state: "attached", timeout: DEFAULT_WAIT_TIMEOUT_MS });

  const deadline = Date.now() + DEFAULT_WAIT_TIMEOUT_MS;
  let value = "";
  while (Date.now() <= deadline) {
    value = ((await locator.textContent()) ?? "").trim();
    if (RECEIPT_ID_PATTERN.test(value) && value === expectedReceiptId) return;
    await sleep(POLL_INTERVAL_MS);
  }
  throw new Error(`receipt ${expectedReceiptId} did not become visible before timeout; last value: ${value}`);
}

export async function readReceiptId(page) {
  const locator = page.locator(".receipt-grid > div").filter({ hasText: "Receipt ID" }).locator("dd");
  if ((await locator.count()) === 0) return null;
  const value = (await locator.first().textContent())?.trim() ?? "";
  return RECEIPT_ID_PATTERN.test(value) ? value : null;
}

export async function assertUiMatchesPayload(page, payload, scenario) {
  requireCondition(payload.initial_decision?.decision === scenario.initial, `${scenario.id}: initial decision drift`);
  requireCondition(payload.effective_decision === scenario.effective, `${scenario.id}: effective decision drift`);
  requireCondition(payload.receipt && RECEIPT_ID_PATTERN.test(payload.receipt.receipt_id), `${scenario.id}: missing receipt`);
  requireCondition(SHA256_PATTERN.test(payload.receipt.content_sha256), `${scenario.id}: invalid receipt hash`);
  await waitForReceipt(page, payload.receipt.receipt_id);
  const initial = (await page.locator(".journey-step").nth(0).locator("strong").textContent())?.trim();
  const effective = (await page.locator(".journey-step").nth(1).locator("strong").textContent())?.trim();
  const display = (await page.locator(".decision-display > strong").textContent())?.trim();
  requireCondition(initial === scenario.initial, `${scenario.id}: UI initial decision mismatch`);
  requireCondition(effective === scenario.effective, `${scenario.id}: UI effective decision mismatch`);
  requireCondition(display === scenario.effective, `${scenario.id}: UI outcome display mismatch`);
  requireCondition((await page.getByRole("alert").count()) === 0, `${scenario.id}: unexpected UI error`);
  requireCondition((await page.getByText("Historical deterministic replay", { exact: true }).count()) === 0, `${scenario.id}: API path fell back to replay`);
}

export async function verifyReceiptLookup(context, origin, payload) {
  const receipt = payload.receipt;
  const response = await context.request.get(`${origin}/api/receipts/${receipt.receipt_id}`);
  requireCondition(response.status() === 200, `receipt lookup failed: ${response.status()}`);
  const lookedUp = await response.json();
  requireCondition(lookedUp.receipt_id === receipt.receipt_id, "receipt lookup ID mismatch");
  requireCondition(lookedUp.content_sha256 === receipt.content_sha256, "receipt lookup hash mismatch");
  requireCondition(!Object.prototype.hasOwnProperty.call(lookedUp, "rows"), "receipt lookup leaked raw rows");
  return { receipt_id: lookedUp.receipt_id, content_sha256: lookedUp.content_sha256, status: response.status(), raw_rows_present: false };
}

export async function verifyMissingReceipt(context, origin) {
  const response = await context.request.get(`${origin}/api/receipts/tj_0000000000000000`);
  requireCondition(response.status() === 404, `missing receipt must return 404, got ${response.status()}`);
  const payload = await response.json();
  requireCondition(payload.detail?.code === "RECEIPT_NOT_FOUND", "missing receipt error code drift");
  return { status: response.status(), code: payload.detail.code };
}

export function verifyHeaders(headers, kind) {
  const normalized = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
  const required = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
  };
  for (const [name, expected] of Object.entries(required)) requireCondition(normalized[name] === expected, `${kind}: invalid ${name}`);
  const csp = normalized["content-security-policy"] ?? "";
  for (const directive of ["default-src 'self'", "frame-ancestors 'none'", "connect-src 'self'"]) {
    requireCondition(csp.includes(directive), `${kind}: CSP missing ${directive}`);
  }
  if (kind === "document") requireCondition(normalized["cache-control"] === "no-cache, max-age=0", "document cache policy drift");
  else {
    requireCondition(normalized["cache-control"] === "no-store, max-age=0", "API cache policy drift");
    requireCondition(normalized.pragma === "no-cache", "API pragma drift");
  }
  return {
    cache_control: normalized["cache-control"],
    content_security_policy: csp,
    cross_origin_opener_policy: normalized["cross-origin-opener-policy"],
    cross_origin_resource_policy: normalized["cross-origin-resource-policy"],
    permissions_policy: normalized["permissions-policy"],
    pragma: normalized.pragma ?? null,
    referrer_policy: normalized["referrer-policy"],
    strict_transport_security: normalized["strict-transport-security"] ?? null,
    x_content_type_options: normalized["x-content-type-options"],
    x_frame_options: normalized["x-frame-options"],
  };
}
