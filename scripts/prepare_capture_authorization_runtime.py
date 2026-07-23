"""Prepare the DataHub UI capture script for the ephemeral capture environment.

The capture harness emits a root-only VIEW_ENTITY_PAGE policy directly to local GMS.
The checked-in browser script historically tried to mutate UI policy state itself. For
capture runs we replace only that function so the browser becomes read-only: it proves
that the GMS-emitted policy has propagated before recording any entity page.

This file exists only on the capture-only PR and is not intended to merge into main.
"""

from __future__ import annotations

from pathlib import Path


SCRIPT = Path("scripts/capture_datahub_video_evidence.mjs")


REPLACEMENT = r'''async function prepareCaptureAuthorization() {
  const me = await executeGraphQL(`
    query CaptureGetMe {
      me {
        corpUser { urn username }
        platformPrivileges { managePolicies }
      }
    }
  `);
  const actorUrn = me?.me?.corpUser?.urn;
  const username = me?.me?.corpUser?.username;
  const managePolicies = Boolean(me?.me?.platformPrivileges?.managePolicies);
  if (actorUrn !== "urn:li:corpuser:datahub") {
    throw new Error(`unexpected DataHub capture actor: ${actorUrn ?? "missing"}`);
  }

  const policyUrn = "urn:li:dataHubPolicy:toxicjoin-capture-view";
  let privileges = [];
  for (let attempt = 1; attempt <= 60; attempt += 1) {
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
    if (privileges.includes("VIEW_ENTITY_PAGE")) break;
    await sleep(1_000);
  }

  authorizationEvidence = {
    username,
    actor_urn: actorUrn,
    manage_policies: managePolicies,
    policy_urn: policyUrn,
    policy_source: "direct-gms-capture-only",
    view_entity_page_granted: privileges.includes("VIEW_ENTITY_PAGE"),
    granted_privileges: [...privileges].sort(),
  };
  fs.writeFileSync(
    path.join(outputDirectory, "capture-authorization.json"),
    `${JSON.stringify(authorizationEvidence, null, 2)}\n`,
    "utf8",
  );

  if (!authorizationEvidence.view_entity_page_granted) {
    throw new Error(
      `VIEW_ENTITY_PAGE was not granted after policy-cache wait: ${JSON.stringify(authorizationEvidence)}`,
    );
  }
}

'''


def main() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    start_marker = "async function prepareCaptureAuthorization() {"
    end_marker = "async function clickEntityTab("
    start = text.index(start_marker)
    end = text.index(end_marker, start)

    patched = text[:start] + REPLACEMENT + text[end:]
    if "CaptureEnableViewEntity" in patched:
        raise RuntimeError("runtime capture patch left a UI policy mutation behind")
    if 'policy_source: "direct-gms-capture-only"' not in patched:
        raise RuntimeError("runtime capture patch did not install the GMS policy verifier")

    SCRIPT.write_text(patched, encoding="utf-8")


if __name__ == "__main__":
    main()
