"""Prepare DataHub authorization and a clean video-capture browser state.

The capture-only branch assigns the local quickstart `datahub` user to DataHub's
built-in Admin role directly through local GMS. It then patches the browser harness
so the bootstrap session proves MANAGE_POLICIES and VIEW_ENTITY_PAGE, dismisses
DataHub onboarding tours, and transfers clean browser state into a second context
that starts Playwright video recording only after setup is complete.

The same runtime patch normalizes the pinned DataHub UI label (`Columns`). This
file exists only on the capture-only PR and is not intended to merge into main.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from datahub.emitter.mcp import MetadataChangeProposalWrapper
from datahub.emitter.rest_emitter import DatahubRestEmitter
from datahub.metadata.schema_classes import RoleMembershipClass


SCRIPT = Path("scripts/capture_datahub_video_evidence.mjs")
CAPTURE_DIR = Path("artifacts/video-captures")
ACTOR_URN = "urn:li:corpuser:datahub"
ADMIN_ROLE_URN = "urn:li:dataHubRole:Admin"


AUTH_REPLACEMENT = r'''async function prepareCaptureAuthorization() {
  const expectedActorUrn = "urn:li:corpuser:datahub";
  const adminRoleUrn = "urn:li:dataHubRole:Admin";
  let username = null;
  let actorUrn = null;
  let managePolicies = false;
  let privileges = [];

  for (let attempt = 1; attempt <= 60; attempt += 1) {
    const me = await executeGraphQL(`
      query CaptureGetMe {
        me {
          corpUser { urn username }
          platformPrivileges { managePolicies }
        }
      }
    `);
    actorUrn = me?.me?.corpUser?.urn ?? null;
    username = me?.me?.corpUser?.username ?? null;
    managePolicies = Boolean(me?.me?.platformPrivileges?.managePolicies);
    if (actorUrn !== expectedActorUrn) {
      throw new Error(`unexpected DataHub capture actor: ${actorUrn ?? "missing"}`);
    }

    const result = await executeGraphQL(
      `query CaptureGrantedPrivileges($input: GetGrantedPrivilegesInput!) {
        getGrantedPrivileges(input: $input) { privileges }
      }`,
      {
        input: {
          actorUrn,
          resourceSpec: {
            resourceType: "DATASET",
            resourceUrn: datasetUrn,
          },
        },
      },
    );
    privileges = result?.getGrantedPrivileges?.privileges ?? [];
    if (managePolicies && privileges.includes("VIEW_ENTITY_PAGE")) break;
    await sleep(1_000);
  }

  authorizationEvidence = {
    username,
    actor_urn: actorUrn,
    role_urn: adminRoleUrn,
    assignment_source: "direct-gms-admin-role-capture-only",
    policy_source: "direct-gms-capture-only",
    manage_policies: managePolicies,
    view_entity_page_granted: privileges.includes("VIEW_ENTITY_PAGE"),
    granted_privileges: [...privileges].sort(),
  };
  fs.writeFileSync(
    path.join(outputDirectory, "capture-authorization.json"),
    `${JSON.stringify(authorizationEvidence, null, 2)}\n`,
    "utf8",
  );

  if (!authorizationEvidence.manage_policies) {
    throw new Error(
      `Admin role did not grant managePolicies after cache wait: ${JSON.stringify(authorizationEvidence)}`,
    );
  }
  if (!authorizationEvidence.view_entity_page_granted) {
    throw new Error(
      `Admin role did not grant VIEW_ENTITY_PAGE after cache wait: ${JSON.stringify(authorizationEvidence)}`,
    );
  }
}

'''


TOUR_DISMISS_HELPER = r'''async function dismissTransientDataHubTour(maxPasses = 8) {
  for (let pass = 0; pass < maxPasses; pass += 1) {
    const tourClose = page.locator("button.reactour__close").first();
    const visible = await tourClose.isVisible({ timeout: 1_500 }).catch(() => false);
    if (!visible) return;
    await tourClose.click();
    await sleep(450);
  }

  const stillVisible = await page
    .locator("button.reactour__close")
    .first()
    .isVisible({ timeout: 750 })
    .catch(() => false);
  if (stillVisible) {
    throw new Error("DataHub onboarding tour remained visible after dismissal passes");
  }
}

'''


CLEAN_RECORDING_HELPERS = r'''async function prepareCleanRecordingState() {
  const bootstrapContext = await browser.newContext(browserContextOptions);
  try {
    page = await bootstrapContext.newPage();
    await loginAsQuickstartAdmin();
    await dismissTransientDataHubTour();
    await prepareCaptureAuthorization();

    await navigateEntity("dataset", datasetUrn);
    await waitForAnyText(
      ["retention_scores", "retention scores", "Retention Scores"],
      45_000,
    );
    await dismissTransientDataHubTour();
    await sleep(800);

    const storageState = await bootstrapContext.storageState();
    const sessionStorageState = await page.evaluate(() =>
      Object.fromEntries(
        Array.from({ length: sessionStorage.length }, (_, index) => {
          const key = sessionStorage.key(index);
          return [key, key === null ? null : sessionStorage.getItem(key)];
        }).filter(([key]) => key !== null),
      ),
    );
    return { storageState, sessionStorageState };
  } finally {
    if (page) await page.close().catch(() => {});
    page = null;
    await bootstrapContext.close().catch(() => {});
  }
}

async function startCleanRecordingContext(cleanState) {
  context = await browser.newContext({
    ...browserContextOptions,
    storageState: cleanState.storageState,
    recordVideo: {
      dir: videoDirectory,
      size: { width: 1920, height: 1080 },
    },
  });
  await context.addInitScript((values) => {
    for (const [key, value] of Object.entries(values)) {
      if (value !== null) window.sessionStorage.setItem(key, value);
    }
  }, cleanState.sessionStorageState);

  page = await context.newPage();
  video = page.video();
  attachRecordingDiagnostics();
}

'''


CONTEXT_REPLACEMENT = r'''const browserContextOptions = {
  viewport: { width: 1920, height: 1080 },
  screen: { width: 1920, height: 1080 },
  deviceScaleFactor: 1,
  reducedMotion: "reduce",
};

let context = null;
let page = null;
let video = null;
const pageErrors = [];
const consoleErrors = [];
const failedRequests = [];
const captured = [];
let authorizationEvidence = null;

function attachRecordingDiagnostics() {
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("requestfailed", (request) => {
    failedRequests.push({
      url: request.url(),
      error: request.failure()?.errorText ?? "unknown",
    });
  });
}
'''


CONTEXT_ORIGINAL = r'''const context = await browser.newContext({
  viewport: { width: 1920, height: 1080 },
  screen: { width: 1920, height: 1080 },
  deviceScaleFactor: 1,
  reducedMotion: "reduce",
  recordVideo: {
    dir: videoDirectory,
    size: { width: 1920, height: 1080 },
  },
});

const page = await context.newPage();
const video = page.video();
const pageErrors = [];
const consoleErrors = [];
const failedRequests = [];
const captured = [];
let authorizationEvidence = null;
page.on("pageerror", (error) => pageErrors.push(String(error)));
page.on("console", (message) => {
  if (message.type() === "error") consoleErrors.push(message.text());
});
page.on("requestfailed", (request) => {
  failedRequests.push({
    url: request.url(),
    error: request.failure()?.errorText ?? "unknown",
  });
});
'''


def assign_capture_admin_role() -> None:
    """Assign only the local quickstart root user to DataHub's built-in Admin role."""

    gms_url = os.environ.get("DATAHUB_GMS_URL", "http://127.0.0.1:8080")
    emitter = DatahubRestEmitter(gms_server=gms_url, extra_headers={})
    emitter.test_connection()
    emitter.emit(
        MetadataChangeProposalWrapper(
            entityUrn=ACTOR_URN,
            aspect=RoleMembershipClass(roles=[ADMIN_ROLE_URN]),
        )
    )

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": "1.0",
        "status": "assigned",
        "actor_urn": ACTOR_URN,
        "role_urn": ADMIN_ROLE_URN,
        "assignment_source": "direct-gms-capture-only",
        "scope": "ephemeral-video-capture-only",
    }
    (CAPTURE_DIR / "capture-role-assignment.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True))


def patch_browser_verifier() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    start_marker = "async function prepareCaptureAuthorization() {"
    end_marker = "async function clickEntityTab("
    start = text.index(start_marker)
    end = text.index(end_marker, start)

    patched = text[:start] + AUTH_REPLACEMENT + text[end:]

    if CONTEXT_ORIGINAL not in patched:
        raise RuntimeError("capture script browser context block changed unexpectedly")
    patched = patched.replace(CONTEXT_ORIGINAL, CONTEXT_REPLACEMENT, 1)

    capture_marker = "async function captureCurrent(name, expectedText, routeMode = null) {"
    capture_wait = (
        "  const matchedText = await waitForAnyText(expectedText, 45_000);\n"
        "  await sleep(1_600);"
    )
    capture_wait_compat = (
        "  const matchedText = await waitForAnyText(expectedText, 45_000);\n"
        "  await dismissTransientDataHubTour();\n"
        "  await sleep(1_600);"
    )
    if capture_marker not in patched:
        raise RuntimeError("capture script no longer contains captureCurrent")
    if capture_wait not in patched:
        raise RuntimeError("capture script no longer contains the expected capture timing block")
    patched = patched.replace(capture_marker, TOUR_DISMISS_HELPER + capture_marker, 1)
    patched = patched.replace(capture_wait, capture_wait_compat, 1)

    schema_click = 'await clickEntityTab("schema-tab", "Schema");'
    schema_click_compat = 'await clickEntityTab("schema-tab", "Columns");'
    schema_expectation = '["churn_score", "customer_id", "Schema"],'
    schema_expectation_compat = '["churn_score", "customer_id", "Columns"],'
    if schema_click not in patched:
        raise RuntimeError("capture script no longer contains the expected Schema tab selector")
    if schema_expectation not in patched:
        raise RuntimeError("capture script no longer contains the expected Schema capture assertion")
    patched = patched.replace(schema_click, schema_click_compat, 1)
    patched = patched.replace(schema_expectation, schema_expectation_compat, 1)

    try_marker = """try {
  await loginAsQuickstartAdmin();
  await prepareCaptureAuthorization();

  await captureEntity("""
    try_replacement = """try {
  const cleanState = await prepareCleanRecordingState();
  await startCleanRecordingContext(cleanState);

  await captureEntity("""
    if try_marker not in patched:
        raise RuntimeError("capture script startup sequence changed unexpectedly")
    patched = patched.replace(try_marker, try_replacement, 1)

    finally_original = """} finally {
  await page.close().catch(() => {});
  await context.close().catch(() => {});
  await browser.close().catch(() => {});
}"""
    finally_replacement = """} finally {
  if (page) await page.close().catch(() => {});
  if (context) await context.close().catch(() => {});
  await browser.close().catch(() => {});
}"""
    if finally_original not in patched:
        raise RuntimeError("capture script cleanup sequence changed unexpectedly")
    patched = patched.replace(finally_original, finally_replacement, 1)

    capture_error_marker = "let captureError = null;"
    if capture_error_marker not in patched:
        raise RuntimeError("capture script no longer contains capture error marker")
    patched = patched.replace(
        capture_error_marker,
        CLEAN_RECORDING_HELPERS + capture_error_marker,
        1,
    )

    if "CaptureEnableViewEntity" in patched:
        raise RuntimeError("runtime capture patch left a UI policy mutation behind")
    if 'assignment_source: "direct-gms-admin-role-capture-only"' not in patched:
        raise RuntimeError("runtime capture patch did not install the Admin-role verifier")
    if 'role_urn: adminRoleUrn' not in patched:
        raise RuntimeError("runtime capture patch did not retain Admin role evidence")
    if "prepareCleanRecordingState" not in patched:
        raise RuntimeError("runtime capture patch did not isolate bootstrap from recording")
    if "dismissTransientDataHubTour" not in patched:
        raise RuntimeError("runtime capture patch did not install tour dismissal")
    if schema_click_compat not in patched or schema_expectation_compat not in patched:
        raise RuntimeError("runtime capture patch did not install the Columns-tab compatibility fix")

    SCRIPT.write_text(patched, encoding="utf-8")


def main() -> None:
    assign_capture_admin_role()
    patch_browser_verifier()


if __name__ == "__main__":
    main()
