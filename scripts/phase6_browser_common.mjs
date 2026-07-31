import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";

export const EXPECTED_PLAYWRIGHT_VERSION = "1.54.1";
export const EXPECTED_NODE_VERSION = "v22.16.0";
export const EXPECTED_NPM_VERSION = "10.9.2";
export const RECEIPT_ID_PATTERN = /^tj_[0-9a-f]{16}$/;
export const SHA256_PATTERN = /^[0-9a-f]{64}$/;
export const SCENARIOS = Object.freeze([
  { id: "rewrite-churn-regions", title: "Rewrite a sensitive churn analysis", initial: "REWRITE", effective: "ALLOW" },
  { id: "allow-public-order-counts", title: "Allow a low-risk aggregate", initial: "ALLOW", effective: "ALLOW" },
  { id: "block-sensitive-export", title: "Block compositional re-identification risk", initial: "BLOCK", effective: "BLOCK" },
]);
export const VIEWPORTS = Object.freeze([
  { name: "desktop", width: 1440, height: 1000, deviceScaleFactor: 1 },
  { name: "mobile", width: 390, height: 844, deviceScaleFactor: 2 },
]);

export function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

export function parseArguments(argv) {
  const parsed = {
    origin: "http://127.0.0.1:18006",
    expectedSha: "",
    outputDir: ".toxicjoin/phase6-browser-e2e",
    container: "toxicjoin-phase6",
    image: "",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    const next = argv[index + 1];
    if (value === "--origin" && next) parsed.origin = next.replace(/\/+$/, "");
    else if (value === "--expected-sha" && next) parsed.expectedSha = next;
    else if (value === "--output-dir" && next) parsed.outputDir = next;
    else if (value === "--container" && next) parsed.container = next;
    else if (value === "--image" && next) parsed.image = next;
    else throw new Error(`unknown or incomplete argument: ${value}`);
    index += 1;
  }
  requireCondition(/^[0-9a-f]{40}$/.test(parsed.expectedSha), "expected SHA must be 40 lowercase hex characters");
  requireCondition(/^https?:\/\//.test(parsed.origin), "origin must be an HTTP(S) URL");
  requireCondition(parsed.container.length > 0, "container name is required");
  requireCondition(parsed.image.length > 0, "image tag is required");
  return parsed;
}

export function runText(command, args) {
  return execFileSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

export async function sha256File(filePath) {
  return sha256Bytes(await readFile(filePath));
}

export async function writeJson(filePath, payload) {
  await writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

export async function listFilesRecursive(rootPath) {
  const results = [];
  async function visit(current) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const child = path.join(current, entry.name);
      if (entry.isDirectory()) await visit(child);
      else if (entry.isFile()) results.push(child);
    }
  }
  await visit(rootPath);
  return results.sort();
}

export function relativePath(rootPath, filePath) {
  return path.relative(rootPath, filePath).split(path.sep).join("/");
}

export function inspectContainer(containerName, imageTag) {
  const container = JSON.parse(runText("docker", ["inspect", containerName]))[0];
  const image = JSON.parse(runText("docker", ["image", "inspect", imageTag]))[0];
  const capDrop = container.HostConfig.CapDrop ?? [];
  const securityOpt = container.HostConfig.SecurityOpt ?? [];
  const runtimeMount = (container.Mounts ?? []).find((mount) => mount.Destination === "/var/lib/toxicjoin");
  requireCondition(container.Config.User === "10001:10001", "production container user drift");
  requireCondition(container.HostConfig.ReadonlyRootfs === true, "production root filesystem is not read-only");
  requireCondition(capDrop.includes("ALL"), "production container did not drop all capabilities");
  requireCondition(securityOpt.includes("no-new-privileges:true"), "production container lacks no-new-privileges");
  requireCondition(runtimeMount?.Type === "volume", "runtime state is not on a Docker volume");
  return {
    container_name: containerName,
    container_id: container.Id,
    image_tag: imageTag,
    image_id: image.Id,
    configured_user: container.Config.User,
    readonly_rootfs: container.HostConfig.ReadonlyRootfs,
    cap_drop: capDrop,
    security_opt: securityOpt,
    runtime_mount: { type: runtimeMount.Type, destination: runtimeMount.Destination, rw: runtimeMount.RW },
    exposed_port: container.NetworkSettings.Ports?.["8000/tcp"] ?? [],
  };
}

export async function captureContainerLog(containerName, outputPath) {
  const logs = spawnSync("docker", ["logs", containerName], { encoding: "utf8" });
  await writeFile(outputPath, `${logs.stdout ?? ""}${logs.stderr ?? ""}`, "utf8");
}

export async function captureScreenshot(page, outputDir, fileName) {
  const screenshotDir = path.join(outputDir, "screenshots");
  await mkdir(screenshotDir, { recursive: true });
  const filePath = path.join(screenshotDir, fileName);
  await page.screenshot({ path: filePath, fullPage: true, animations: "disabled", caret: "hide" });
  return {
    path: relativePath(outputDir, filePath),
    sha256: await sha256File(filePath),
    size_bytes: (await stat(filePath)).size,
    capture_method: "playwright-real-production-browser",
    generated_ui: false,
  };
}

export async function auditAccessibilityAndLayout(page, viewport) {
  const result = await page.evaluate(() => {
    const labelledBy = (element) => (element.getAttribute("aria-labelledby") ?? "")
      .split(/\s+/).filter(Boolean).map((id) => document.getElementById(id)?.textContent ?? "").join(" ").trim();
    const accessibleName = (element) => (
      element.getAttribute("aria-label")?.trim() ||
      labelledBy(element) ||
      element.getAttribute("alt")?.trim() ||
      element.getAttribute("title")?.trim() ||
      element.textContent?.replace(/\s+/g, " ").trim() ||
      ""
    );
    const interactive = [...document.querySelectorAll('button, a[href], input, select, textarea, [role="button"], [role="link"]')];
    const unnamed = interactive.filter((element) => !accessibleName(element)).map((element) => element.outerHTML.slice(0, 200));
    const outside = interactive.map((element) => ({ element, rect: element.getBoundingClientRect() }))
      .filter(({ rect }) => rect.width > 0 && rect.height > 0)
      .filter(({ rect }) => rect.left < -1 || rect.right > window.innerWidth + 1)
      .map(({ element, rect }) => ({ tag: element.tagName, name: accessibleName(element), left: rect.left, right: rect.right }));
    const ids = [...document.querySelectorAll("[id]")].map((element) => element.id).filter(Boolean);
    const documentWidth = Math.max(document.documentElement.scrollWidth, document.body?.scrollWidth ?? 0);
    return {
      document_title: document.title,
      html_lang: document.documentElement.lang,
      h1_count: document.querySelectorAll("h1").length,
      header_count: document.querySelectorAll("header").length,
      main_count: document.querySelectorAll("main").length,
      footer_count: document.querySelectorAll("footer").length,
      nav_count: document.querySelectorAll("nav").length,
      duplicate_ids: [...new Set(ids.filter((id, index) => ids.indexOf(id) !== index))],
      unnamed_interactive: unnamed,
      visible_interactive_outside_viewport: outside,
      horizontal_overflow_px: Math.max(0, documentWidth - window.innerWidth),
      viewport_width: window.innerWidth,
      viewport_height: window.innerHeight,
    };
  });
  requireCondition(result.document_title.includes("ToxicJoin"), "document title missing product identity");
  requireCondition(result.html_lang === "en", "document language must be en");
  requireCondition(result.h1_count === 1, `expected one h1, found ${result.h1_count}`);
  requireCondition(result.header_count >= 1 && result.main_count === 1 && result.footer_count >= 1 && result.nav_count >= 2, "semantic landmark contract failed");
  requireCondition(result.duplicate_ids.length === 0, "duplicate DOM IDs detected");
  requireCondition(result.unnamed_interactive.length === 0, "unnamed interactive controls detected");
  requireCondition(result.visible_interactive_outside_viewport.length === 0, `${viewport.name}: interactive controls overflow horizontally`);
  requireCondition(result.horizontal_overflow_px <= 1, `${viewport.name}: horizontal overflow ${result.horizontal_overflow_px}px`);
  await page.evaluate(() => document.activeElement instanceof HTMLElement && document.activeElement.blur());
  await page.keyboard.press("Tab");
  const focused = await page.evaluate(() => {
    const element = document.activeElement;
    if (!(element instanceof HTMLElement)) return { tag: "", name: "" };
    return {
      tag: element.tagName,
      name: element.getAttribute("aria-label")?.trim() || element.textContent?.replace(/\s+/g, " ").trim() || element.getAttribute("title")?.trim() || "",
    };
  });
  requireCondition(["A", "BUTTON"].includes(focused.tag) && focused.name.length > 0, "keyboard focus did not enter a named interactive control");
  return { ...result, first_tab_stop: focused };
}
