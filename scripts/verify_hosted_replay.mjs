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

const browser = await chromium.launch({
  headless: true,
  executablePath,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

const report = {
  schema_version: "1.0",
  replay_url: replayUrl,
  verified_at: new Date().toISOString(),
  browser_executable: executablePath,
  disclosure: null,
  profiles: [],
};

try {
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
      if (response.url().includes("/toxicjoin/assets/")) {
        assetResponses.push({ url: response.url(), status: response.status() });
      }
    });

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
    for (const required of [
      "ToxicJoin",
      "Initial policy",
      "REWRITE",
      "After remediation",
      "ALLOW",
      "30",
      "False allows",
      "0",
    ]) {
      if (!bodyText.includes(required)) {
        throw new Error(`${profile.name}: missing required text ${required}`);
      }
    }

    const layout = await page.evaluate(() => ({
      innerWidth: window.innerWidth,
      scrollWidth: document.documentElement.scrollWidth,
      bodyScrollWidth: document.body.scrollWidth,
    }));
    if (
      layout.scrollWidth > layout.innerWidth + 1 ||
      layout.bodyScrollWidth > layout.innerWidth + 1
    ) {
      throw new Error(`${profile.name}: horizontal overflow ${JSON.stringify(layout)}`);
    }

    if (consoleErrors.length) {
      throw new Error(`${profile.name}: console errors: ${consoleErrors.join(" | ")}`);
    }
    if (pageErrors.length) {
      throw new Error(`${profile.name}: page errors: ${pageErrors.join(" | ")}`);
    }
    if (failedRequests.length) {
      throw new Error(
        `${profile.name}: failed requests: ${JSON.stringify(failedRequests)}`,
      );
    }
    if (assetResponses.length < 2) {
      throw new Error(`${profile.name}: expected JavaScript and CSS assets`);
    }
    const badAssets = assetResponses.filter((asset) => asset.status >= 400);
    if (badAssets.length) {
      throw new Error(
        `${profile.name}: failed static assets: ${JSON.stringify(badAssets)}`,
      );
    }

    const screenshot = path.join(outputDirectory, `${profile.name}.png`);
    await page.screenshot({ path: screenshot, fullPage: true });

    const disclosure = await notice.innerText();
    report.disclosure = disclosure;
    report.profiles.push({
      name: profile.name,
      viewport: { width: profile.width, height: profile.height },
      document_status: response.status(),
      asset_count: assetResponses.length,
      horizontal_overflow: false,
      console_error_count: 0,
      page_error_count: 0,
      failed_request_count: 0,
      screenshot,
    });
    await context.close();
  }
} finally {
  await browser.close();
}

if (!report.disclosure?.includes("no live execution or DataHub write is being claimed")) {
  throw new Error("Replay disclosure was not captured exactly");
}

fs.writeFileSync(
  path.join(outputDirectory, "verification.json"),
  `${JSON.stringify(report, null, 2)}\n`,
  "utf8",
);
console.log(JSON.stringify(report, null, 2));
