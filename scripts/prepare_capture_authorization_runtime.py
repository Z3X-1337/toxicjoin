"""Prepare DataHub authorization for the ephemeral video-capture environment.

The capture-only branch assigns the local quickstart `datahub` user to DataHub's
built-in Admin role directly through local GMS. It then replaces only the browser
authorization function so Chrome becomes read-only: the session proves that the
role assignment propagated and that DataHub grants both MANAGE_POLICIES and
VIEW_ENTITY_PAGE before recording any entity page.

This file exists only on the capture-only PR and is not intended to merge into main.
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


REPLACEMENT = r'''async function prepareCaptureAuthorization() {
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

    patched = text[:start] + REPLACEMENT + text[end:]
    if "CaptureEnableViewEntity" in patched:
        raise RuntimeError("runtime capture patch left a UI policy mutation behind")
    if 'assignment_source: "direct-gms-admin-role-capture-only"' not in patched:
        raise RuntimeError("runtime capture patch did not install the Admin-role verifier")
    if 'role_urn: adminRoleUrn' not in patched:
        raise RuntimeError("runtime capture patch did not retain Admin role evidence")

    SCRIPT.write_text(patched, encoding="utf-8")


def main() -> None:
    assign_capture_admin_role()
    patch_browser_verifier()


if __name__ == "__main__":
    main()
