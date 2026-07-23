import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright-core";

const replayUrl = process.env.REPLAY_URL;
const executablePath = process.env.BROWSER_EXECUTABLE;

if (!replayUrl) {
  throw new Error("REPLAY_URL is required");
}
if (!executablePath || !fs.existsSync(executablePath)) {
  throw new Error(`BROWSER_EXECUTABLE is missing or invalid: ${executablePath ?? "unset"}`);
}

const profiles = [
  { name: "desktop", width: 1440, height: 1000 },
  { name: "mobile", width: 390, height: 844 },
];

const outputDirectory = path.join("artifacts", "hosted-replay");
fs.mkdirSync(outputDirectory, { recursive: true });

const report = {
  schema_version: "1.0",
  replay_url: replayUrl,
  verified_at: new Date().toISOString(),
  browser_executable: executablePath,
  disclosure: null,
  profiles: [],
};

const diagnostics = {
  schema_version: "1.0",
  replay_url: replayUrl,
  captured_at: new Date().toISOString(),
  profiles: [],
};

let browser;
try {
  browser = await chromium.launch({
    headless: true,
    executablePath,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });

  for (const profile of profiles) {
    const context = await browser.newContext({
      viewport: { width: profile.width, height: profile.height },
      deviceScaleFactor: 1,
      reducedMotion: "reduce",
    });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    const failedRequests = [];
    const assetResponses = [];
    const apiResponses = [];

    page.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    page.on("pageerror", (error) => pageErrors.push(String(error)));
    page.on("requestfailed", (request) => {
      failedRequests.push({
        url: request.url(),
        failure: request.failure()?.errorText ?? "unknown",
      });
    });
    page.on("response", (response) => {
      const url = response.url();
      if (url.includes("cdn.jsdelivr.net/gh/Z3X-1337/toxicjoin@")) {
        assetResponses.push({ url, status: response.status() });
      }
      if (new URL(url).pathname.startsWith("/api/")) {
        apiResponses.push({ url, status: response.status() });
      }
    });

    try {
      const response = await page.goto(replayUrl, {
        waitUntil: "networkidle",
        timeout: 60_000,
      });
      if (!response || response.status() !== 200) {
        throw new Error(`${profile.name}: expected document HTTP 200`);
      }

      await page.getByText("Deterministic replay", { exact: true }).waitFor({
        state: "visible",
        timeout: 30_000,
      });
      const notice = page.getByText(
        /no live execution or DataHub write is being claimed/i,
      );
      await notice.waitFor({ state: "visible", timeout: 30_000 });
      await page.getByRole("heading", { name: "Measured, not narrated" }).waitFor({
        state: "visible",
        timeout: 30_000,
      });
      await page.getByText("False allows", { exact: true }).waitFor({
        state: "visible",
        timeout: 30_000,
      });
      await page.getByText("After remediation", { exact: true }).waitFor({
        state: "visible",
        timeout: 30_000,
      });

      const bodyText = await page.locator("body").innerText();
      const layout = await page.evaluate(() => ({
        innerWidth: window.innerWidth,
        scrollWidth: document.documentElement.scrollWidth,
        bodyScrollWidth: document.body.scrollWidth,
      }));
      const screenshot = path.join(outputDirectory, `${profile.name}.png`);
      await page.screenshot({ path: screenshot, fullPage: true });

      const expectedFallbackResponses = apiResponses.filter(
        (entry) => entry.status === 404,
      );
      const expectedNetworkConsoleErrors = consoleErrors.filter((message) =>
        /failed to load resource.*404/i.test(message),
      );
      const unexpectedConsoleErrors = consoleErrors.filter(
        (message) => !/failed to load resource.*404/i.test(message),
      );

      diagnostics.profiles.push({
        name: profile.name,
        viewport: { width: profile.width, height: profile.height },
        body_text: bodyText,
        layout,
        console_errors: consoleErrors,
        page_errors: pageErrors,
        failed_requests: failedRequests,
        asset_responses: assetResponses,
        api_responses: apiResponses,
        screenshot,
      });

      const renderedText = bodyText.toUpperCase();
      for (const required of [
        "TOXICJOIN",
        "INITIAL POLICY",
        "REWRITE",
        "AFTER REMEDIATION",
        "ALLOW",
        "30",
        "FALSE ALLOWS",
        "0",
      ]) {
        if (!renderedText.includes(required)) {
          throw new Error(`${profile.name}: missing required rendered text ${required}`);
        }
      }

      if (
        layout.scrollWidth > layout.innerWidth + 1 ||
        layout.bodyScrollWidth > layout.innerWidth + 1
      ) {
        throw new Error(`${profile.name}: horizontal overflow ${JSON.stringify(layout)}`);
      }
      if (unexpectedConsoleErrors.length) {
        throw new Error(
          `${profile.name}: unexpected console errors: ${unexpectedConsoleErrors.join(" | ")}`,
        );
      }
      if (expectedNetworkConsoleErrors.length > 3) {
        throw new Error(
          `${profile.name}: too many expected network console errors: ${expectedNetworkConsoleErrors.join(" | ")}`,
        );
      }
      if (pageErrors.length) {
        throw new Error(`${profile.name}: page errors: ${pageErrors.join(" | ")}`);
      }
      if (failedRequests.length) {
        throw new Error(
          `${profile.name}: failed requests: ${JSON.stringify(failedRequests)}`,
        );
      }
      if (assetResponses.length !== 2) {
        throw new Error(
          `${profile.name}: expected exactly two immutable JavaScript/CSS assets, got ${assetResponses.length}`,
        );
      }
      const badAssets = assetResponses.filter((asset) => asset.status >= 400);
      if (badAssets.length) {
        throw new Error(
          `${profile.name}: failed static assets: ${JSON.stringify(badAssets)}`,
        );
      }
      if (expectedFallbackResponses.length !== 3) {
        throw new Error(
          `${profile.name}: expected three API 404 responses before replay fallback, got ${JSON.stringify(apiResponses)}`,
        );
      }

      const disclosure = await notice.innerText();
      report.disclosure = disclosure;
      report.profiles.push({
        name: profile.name,
        viewport: { width: profile.width, height: profile.height },
        document_status: response.status(),
        immutable_asset_count: assetResponses.length,
        replay_fallback_api_response_count: expectedFallbackResponses.length,
        expected_network_console_error_count: expectedNetworkConsoleErrors.length,
        horizontal_overflow: false,
        unexpected_console_error_count: 0,
        page_error_count: 0,
        failed_request_count: 0,
        screenshot,
      });
    } finally {
      await context.close();
    }
  }

  if (!report.disclosure?.includes("no live execution or DataHub write is being claimed")) {
    throw new Error("Replay disclosure was not captured exactly");
  }

  fs.writeFileSync(
    path.join(outputDirectory, "verification.json"),
    `${JSON.stringify(report, null, 2)}\n`,
    "utf8",
  );
  fs.writeFileSync(
    path.join(outputDirectory, "diagnostics.json"),
    `${JSON.stringify(diagnostics, null, 2)}\n`,
    "utf8",
  );
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  const failure = {
    schema_version: "1.0",
    replay_url: replayUrl,
    failed_at: new Date().toISOString(),
    error: error instanceof Error ? error.message : String(error),
    diagnostics,
  };
  fs.writeFileSync(
    path.join(outputDirectory, "failure.json"),
    `${JSON.stringify(failure, null, 2)}\n`,
    "utf8",
  );
  console.error(error);
  process.exitCode = 1;
} finally {
  if (browser) {
    await browser.close();
  }
}
