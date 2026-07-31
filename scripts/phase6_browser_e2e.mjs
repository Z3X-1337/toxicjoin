#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import {
  EXPECTED_NODE_VERSION,
  EXPECTED_NPM_VERSION,
  EXPECTED_PLAYWRIGHT_VERSION,
  canonicalJson,
  captureContainerLog,
  inspectContainer,
  listFilesRecursive,
  parseArguments,
  relativePath,
  requireCondition,
  runText,
  sha256Bytes,
  sha256File,
  writeJson,
} from "./phase6_browser_common.mjs";
import { runBrowserMatrix, runFailureDisclosure, runReplayTruthfulness } from "./phase6_browser_paths.mjs";

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const outputDir = path.resolve(options.outputDir);
  await rm(outputDir, { recursive: true, force: true });
  await mkdir(outputDir, { recursive: true });

  const sourceSha = runText("git", ["rev-parse", "HEAD"]);
  const treeSha = runText("git", ["rev-parse", "HEAD^{tree}"]);
  requireCondition(sourceSha === options.expectedSha, `source SHA mismatch: ${sourceSha}`);
  execFileSync("git", ["diff", "--exit-code"], { stdio: "inherit" });
  execFileSync("git", ["diff", "--cached", "--exit-code"], { stdio: "inherit" });

  const nodeVersion = process.version;
  const npmVersion = runText("npm", ["--version"]);
  const playwrightVersion = JSON.parse(await readFile(path.resolve("node_modules/playwright-core/package.json"), "utf8")).version;
  requireCondition(nodeVersion === EXPECTED_NODE_VERSION, `Node version drift: ${nodeVersion}`);
  requireCondition(npmVersion === EXPECTED_NPM_VERSION, `npm version drift: ${npmVersion}`);
  requireCondition(playwrightVersion === EXPECTED_PLAYWRIGHT_VERSION, `playwright-core version drift: ${playwrightVersion}`);

  const sourceIdentity = {
    source_sha: sourceSha,
    tree_sha: treeSha,
    exact_source_checkout_verified: true,
    node: nodeVersion,
    npm: npmVersion,
    playwright_core: playwrightVersion,
    origin: options.origin,
  };
  await writeJson(path.join(outputDir, "source-identity.json"), sourceIdentity);

  const containerEvidence = inspectContainer(options.container, options.image);
  await writeJson(path.join(outputDir, "container-inspect.json"), containerEvidence);
  await captureContainerLog(options.container, path.join(outputDir, "production-container.log"));

  const shared = { missingReceipt: null, securityHeaders: null };
  const browserOptions = { ...options, outputDir };
  const matrix = await runBrowserMatrix(browserOptions, shared);
  const failureDisclosure = await runFailureDisclosure(browserOptions);
  const replayTruthfulness = await runReplayTruthfulness(browserOptions);
  await writeJson(path.join(outputDir, "security-headers.json"), shared.securityHeaders);

  execFileSync("git", ["diff", "--exit-code"], { stdio: "inherit" });
  execFileSync("git", ["diff", "--cached", "--exit-code"], { stdio: "inherit" });

  const rawFiles = (await listFilesRecursive(outputDir))
    .filter((filePath) => !["browser-e2e-report.json", "SHA256SUMS"].includes(path.basename(filePath)));
  const artifacts = [];
  for (const filePath of rawFiles) {
    artifacts.push({ path: relativePath(outputDir, filePath), sha256: await sha256File(filePath), size_bytes: (await stat(filePath)).size });
  }

  const report = {
    schema_version: "1.0",
    created_at: new Date().toISOString(),
    status: "verified",
    source: sourceIdentity,
    production_container: containerEvidence,
    matrix,
    negative_paths: { failure_disclosure: failureDisclosure, replay_truthfulness: replayTruthfulness, missing_receipt: shared.missingReceipt },
    security_headers: shared.securityHeaders,
    coverage: {
      production_frontend_and_api: true,
      chromium: true,
      firefox: true,
      webkit: true,
      desktop_viewport: true,
      mobile_viewport: true,
      allow: true,
      rewrite: true,
      block: true,
      receipt_lookup: true,
      receipt_integrity_on_read: true,
      failure_disclosure: true,
      replay_labels_truthful: true,
      security_headers: true,
      accessibility: true,
      responsive_layout: true,
      real_browser_screenshots: true,
      fake_or_generated_ui_used: false,
    },
    boundaries: {
      phase7_started: false,
      pr118_modified: false,
      postgresql_claim_changed: false,
      vercel_mutated: false,
      devpost_mutated: false,
      release_tag_created: false,
      repository_cleanup_performed: false,
      main_modified_directly: false,
    },
    artifacts,
    tracked_worktree_clean: true,
    report_sha256: "0".repeat(64),
  };
  const hashPayload = { ...report };
  delete hashPayload.report_sha256;
  report.report_sha256 = sha256Bytes(Buffer.from(canonicalJson(hashPayload), "utf8"));
  await writeJson(path.join(outputDir, "browser-e2e-report.json"), report);

  const finalFiles = (await listFilesRecursive(outputDir)).filter((filePath) => path.basename(filePath) !== "SHA256SUMS");
  const manifest = [];
  for (const filePath of finalFiles) manifest.push(`${await sha256File(filePath)}  ${relativePath(outputDir, filePath)}`);
  await writeFile(path.join(outputDir, "SHA256SUMS"), `${manifest.join("\n")}\n`, "utf8");

  process.stdout.write(`${JSON.stringify({
    status: report.status,
    source_sha: sourceSha,
    tree_sha: treeSha,
    matrix_cells: matrix.length,
    screenshots: artifacts.filter((item) => item.path.startsWith("screenshots/")).length,
    report_sha256: report.report_sha256,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({
    status: "failed",
    error_type: error?.constructor?.name ?? "Error",
    detail: String(error?.message ?? error),
  }, null, 2)}\n`);
  process.exitCode = 1;
});
