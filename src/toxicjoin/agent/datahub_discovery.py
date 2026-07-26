"""Security-owned read-only DataHub discovery for the planning-only agent boundary."""

from __future__ import annotations

import base64
import re
import unicodedata
from collections.abc import Callable, Iterator, Mapping
from urllib.parse import parse_qsl, quote, unquote_to_bytes, urlsplit

from pydantic import SecretStr

from toxicjoin.agent.models import (
    AgentDataContext,
    AgentDatasetView,
    AgentFieldView,
    AgentLineageView,
    build_agent_data_context,
)
from toxicjoin.context.datahub import (
    DataHubAssetMap,
    DataHubSnapshot,
    DataHubSnapshotLoader,
)
from toxicjoin.integrations.datahub_authority import (
    DataHubMcpRole,
    ReadOnlyDataHubMcpSettings,
    RoleBoundDataHubMcpClient,
    clone_read_only_settings_for_child,
)
from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpTransport,
    StdioDataHubMcpTransport,
)

_DATASET_URN_PATTERN = re.compile(
    r"^urn:li:dataset:\("
    r"urn:li:dataPlatform:(?P<platform>[^,()]+),"
    r"(?P<dataset>[^,()]+),"
    r"(?P<environment>[^,()]+)"
    r"\)$"
)
_PLATFORM_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
_DATASET_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/+~-"
_ENVIRONMENT_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"

_SECRET_ENV_HINTS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "AUTH",
    "CREDENTIAL",
    "BEARER",
)
_PROXY_ENV_NAMES = frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
    }
)
_SECRET_CLI_HINTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "api-key",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "bearer",
)
_SECRET_TEXT_MARKERS = (
    "bearer ",
    "token=",
    "token:",
    "secret=",
    "secret:",
    "password=",
    "password:",
    "passwd=",
    "passwd:",
    "api-key=",
    "api-key:",
    "api_key=",
    "api_key:",
    "apikey=",
    "apikey:",
    "credential=",
    "credential:",
)
_MIN_SECRET_FRAGMENT_LENGTH = 8
_MAX_VARIANT_SOURCE_BYTES = 4096


class AgentDataHubDiscoveryError(RuntimeError):
    """Stable fail-closed error for agent-facing DataHub discovery."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


TransportFactory = Callable[[ReadOnlyDataHubMcpSettings], DataHubMcpTransport]


class _AgentMetadataSecretGuard:
    """Reject direct/common-encoding reflections of child secrets into Agent metadata.

    A compromised metadata authority already knows the credential presented to it and can encode
    information through an arbitrary covert channel. No finite string filter can provide
    information-theoretic noninterference against that threat. This guard enforces the narrower,
    auditable boundary ToxicJoin can actually prove here: values delivered to the child as
    credentials or secret-bearing configuration must not be reflected directly, embedded in a
    larger planner-visible string, or returned through common reversible encodings.

    The guard exists only for one ``discover()`` call and is never attached to Agent artifacts.
    """

    __slots__ = ("_exact_variants", "_substring_variants")

    def __init__(self, sensitive_values: set[str]) -> None:
        exact_variants: set[str] = set()
        substring_variants: set[str] = set()
        for value in sensitive_values:
            for variant in _secret_text_variants(value):
                exact_variants.add(variant)
                if len(variant) >= _MIN_SECRET_FRAGMENT_LENGTH:
                    substring_variants.add(variant)

        self._exact_variants = frozenset(exact_variants)
        self._substring_variants = tuple(
            sorted(substring_variants, key=lambda item: (-len(item), item))
        )

    @classmethod
    def from_runtime_settings(
        cls,
        settings: ReadOnlyDataHubMcpSettings,
    ) -> "_AgentMetadataSecretGuard":
        sensitive_values: set[str] = set()

        token = settings.gms_token
        if type(token) is not SecretStr:
            raise TypeError("DataHub bearer wrapper is malformed")
        _add_guard_value(sensitive_values, token.get_secret_value())
        _add_url_guard_values(sensitive_values, settings.gms_url)

        child_environment = settings.child_environment()
        for name, value in child_environment.items():
            if _environment_value_is_sensitive(name):
                _add_guard_value(sensitive_values, value)
                _add_url_guard_values(sensitive_values, value)
            elif name in _PROXY_ENV_NAMES:
                _add_guard_value(sensitive_values, value)
                _add_url_guard_values(sensitive_values, value)

        _add_cli_guard_values(sensitive_values, settings.args)
        return cls(sensitive_values)

    def assert_context_safe(self, context: AgentDataContext) -> None:
        try:
            payload = context.model_dump(mode="python")
            for text in _iter_planner_visible_text(payload):
                normalized = _exact_guard_text(text)
                if normalized in self._exact_variants:
                    raise AgentDataHubDiscoveryError(
                        "AGENT_DATAHUB_SECRET_REFLECTION"
                    )
                if any(
                    variant in normalized for variant in self._substring_variants
                ):
                    raise AgentDataHubDiscoveryError(
                        "AGENT_DATAHUB_SECRET_REFLECTION"
                    )
        except AgentDataHubDiscoveryError:
            raise
        except Exception:
            raise AgentDataHubDiscoveryError(
                "AGENT_DATAHUB_SECRET_REFLECTION"
            ) from None


class DataHubAgentDiscoverer:
    """Acquire one trusted DataHub snapshot and expose only a sanitized planning view.

    Discovery requires an unchanged registry-issued dedicated READ_ONLY credential. The
    authority module, not caller-owned settings, owns issuance provenance and produces detached
    registered credentials both at construction and immediately before each transport launch.
    """

    def __init__(
        self,
        *,
        settings: ReadOnlyDataHubMcpSettings,
        asset_map: DataHubAssetMap,
        transport_factory: TransportFactory = StdioDataHubMcpTransport,
    ) -> None:
        self._settings = _read_only_settings(settings)
        self._asset_map = DataHubAssetMap.model_validate(asset_map.model_dump(mode="json"))
        self._transport_factory = transport_factory

    async def discover(self) -> AgentDataContext:
        """Return one immutable, explicitly non-authoritative planning context."""

        try:
            runtime_settings = clone_read_only_settings_for_child(self._settings)
            if runtime_settings is None:
                raise RuntimeError("registered read credential changed before discovery")
            secret_guard = _AgentMetadataSecretGuard.from_runtime_settings(runtime_settings)
            transport = self._transport_factory(runtime_settings)
            async with transport:
                client = RoleBoundDataHubMcpClient(
                    transport,
                    role=DataHubMcpRole.READ_ONLY,
                )
                snapshot = await DataHubSnapshotLoader(
                    client,
                    self._asset_map,
                ).load(require_mutations=False)
        except Exception:
            raise AgentDataHubDiscoveryError("AGENT_DATAHUB_DISCOVERY_FAILED") from None

        context = build_agent_data_context_from_snapshot(snapshot)
        secret_guard.assert_context_safe(context)
        return context


def build_agent_data_context_from_snapshot(snapshot: DataHubSnapshot) -> AgentDataContext:
    """Project a validated DataHub snapshot into the planning-only agent schema.

    Snapshot serialization and validation are one redacted boundary because unconstrained
    MCP-derived payload fragments can contain non-JSON values or attacker-controlled details.
    Fixed identity failures remain stable codes; every other projection failure is collapsed.

    Runtime credential-reflection checks are intentionally performed by ``DataHubAgentDiscoverer``
    because an offline snapshot does not carry the live child credential/configuration material.
    """

    try:
        serialized = snapshot.model_dump(mode="json")
        trusted = DataHubSnapshot.model_validate(serialized)
    except Exception:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SNAPSHOT_INVALID") from None

    try:
        return _project_trusted_snapshot(trusted)
    except AgentDataHubDiscoveryError:
        raise
    except Exception:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_PROJECTION_FAILED") from None


def _project_trusted_snapshot(snapshot: DataHubSnapshot) -> AgentDataContext:
    dataset_views: list[AgentDatasetView] = []
    for logical_name, dataset in sorted(snapshot.catalog.datasets.items()):
        if not _is_canonical_dataset_urn(dataset.urn):
            raise AgentDataHubDiscoveryError("AGENT_DATAHUB_DATASET_IDENTITY_INVALID")

        field_views: list[AgentFieldView] = []
        for field_path, field in sorted(dataset.fields.items()):
            lineage_views: list[AgentLineageView] = []
            for source in field.lineage_sources:
                source_urn = source.datahub_urn
                if source_urn is None:
                    raise AgentDataHubDiscoveryError(
                        "AGENT_DATAHUB_LINEAGE_IDENTITY_UNRESOLVED"
                    )
                if not _is_canonical_dataset_urn(source_urn):
                    raise AgentDataHubDiscoveryError(
                        "AGENT_DATAHUB_LINEAGE_IDENTITY_INVALID"
                    )
                lineage_views.append(
                    AgentLineageView(
                        source_dataset_urn=source_urn,
                        source_field_path=source.ref.field_path,
                        category=source.category,
                        security_authoritative=False,
                    )
                )

            ordered_lineage = tuple(
                sorted(
                    lineage_views,
                    key=lambda item: (item.source_dataset_urn, item.source_field_path),
                )
            )
            if len({item.key for item in ordered_lineage}) != len(ordered_lineage):
                raise AgentDataHubDiscoveryError("AGENT_DATAHUB_LINEAGE_DUPLICATE")

            field_views.append(
                AgentFieldView(
                    field_path=field_path,
                    category=field.category,
                    tags=tuple(sorted(set(field.tags))),
                    glossary_terms=tuple(sorted(set(field.glossary_terms))),
                    lineage=ordered_lineage,
                    security_authoritative=False,
                )
            )

        dataset_views.append(
            AgentDatasetView(
                logical_name=logical_name,
                dataset_urn=dataset.urn,
                owner=dataset.owner,
                domain=dataset.domain,
                fields=tuple(field_views),
                security_authoritative=False,
            )
        )

    return build_agent_data_context(
        source_snapshot_sha256=snapshot.snapshot_sha256,
        catalog_version=snapshot.catalog.version,
        datasets=tuple(dataset_views),
    )


def _read_only_settings(settings: ReadOnlyDataHubMcpSettings) -> ReadOnlyDataHubMcpSettings:
    """Obtain a detached child credential from the authority-owned issuance registry."""

    try:
        copied = clone_read_only_settings_for_child(settings)
    except Exception:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SETTINGS_INVALID") from None
    if copied is None:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_READ_ROLE_REQUIRED")
    try:
        if copied.gms_token is settings.gms_token:
            raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SETTINGS_INVALID")
    except AgentDataHubDiscoveryError:
        raise
    except Exception:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SETTINGS_INVALID") from None
    return copied


def _environment_value_is_sensitive(name: str) -> bool:
    normalized = _exact_guard_text(name).upper()
    return any(hint in normalized for hint in _SECRET_ENV_HINTS)


def _add_cli_guard_values(values: set[str], args: tuple[str, ...]) -> None:
    pending_secret_value = False
    for raw_argument in args:
        argument = _exact_guard_text(raw_argument)
        if pending_secret_value:
            _add_guard_value(values, argument)
            _add_url_guard_values(values, argument)
            pending_secret_value = False
            continue

        handled_assignment = False
        if "=" in argument:
            name, value = argument.split("=", 1)
            if _cli_name_is_sensitive(name):
                _add_guard_value(values, value)
                _add_url_guard_values(values, value)
                handled_assignment = True

        if (
            not handled_assignment
            and argument.startswith("-")
            and _cli_name_is_sensitive(argument.rstrip("="))
        ):
            pending_secret_value = True

        lowered = argument.lower()
        for marker in _SECRET_TEXT_MARKERS:
            index = lowered.find(marker)
            if index < 0:
                continue
            value = argument[index + len(marker) :].strip()
            if value:
                _add_guard_value(values, value)
                _add_url_guard_values(values, value)
            break


def _cli_name_is_sensitive(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in _SECRET_CLI_HINTS)


def _add_url_guard_values(values: set[str], value: str) -> None:
    text = _exact_guard_text(value).strip()
    if not text:
        return
    try:
        parsed = urlsplit(text)
    except ValueError:
        return
    if not parsed.scheme or not parsed.netloc:
        return

    for candidate in (
        text,
        parsed.netloc,
        parsed.hostname,
        parsed.username,
        parsed.password,
        parsed.fragment or None,
    ):
        if candidate:
            _add_guard_value(values, candidate)

    try:
        query_pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=False,
        )
    except ValueError:
        query_pairs = []
    for _, query_value in query_pairs:
        if query_value:
            _add_guard_value(values, query_value)


def _add_guard_value(values: set[str], value: object) -> None:
    text = _exact_guard_text(value).strip()
    if text:
        values.add(text)


def _secret_text_variants(value: str) -> frozenset[str]:
    text = _exact_guard_text(value)
    if not text:
        return frozenset()

    variants = {text}
    encoded = text.encode("utf-8")
    if len(encoded) <= _MAX_VARIANT_SOURCE_BYTES:
        percent_encoded = quote(text, safe="", encoding="utf-8", errors="strict")
        variants.add(percent_encoded)

        standard_b64 = base64.b64encode(encoded).decode("ascii")
        urlsafe_b64 = base64.urlsafe_b64encode(encoded).decode("ascii")
        variants.update(
            {
                standard_b64,
                standard_b64.rstrip("="),
                urlsafe_b64,
                urlsafe_b64.rstrip("="),
                encoded.hex(),
                encoded.hex().upper(),
            }
        )
    return frozenset(item for item in variants if item)


def _iter_planner_visible_text(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield _exact_guard_text(value)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _iter_planner_visible_text(key)
            yield from _iter_planner_visible_text(item)
        return
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            yield from _iter_planner_visible_text(item)


def _exact_guard_text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("Agent metadata guard expected text")
    exact = str.__str__(value)
    if type(exact) is not str:
        raise TypeError("Agent metadata guard text normalization failed")
    return exact


def _is_canonical_dataset_urn(value: str) -> bool:
    if not isinstance(value, str) or len(value) > 2048:
        return False
    match = _DATASET_URN_PATTERN.fullmatch(value)
    if match is None:
        return False

    platform = match.group("platform")
    dataset = match.group("dataset")
    environment = match.group("environment")
    if not _is_canonical_urn_component(platform, safe=_PLATFORM_SAFE):
        return False
    if not _is_canonical_urn_component(dataset, safe=_DATASET_SAFE):
        return False
    if not _is_canonical_urn_component(environment, safe=_ENVIRONMENT_SAFE):
        return False

    canonical = (
        "urn:li:dataset:(urn:li:dataPlatform:"
        f"{platform},{dataset},{environment})"
    )
    return canonical == value


def _is_canonical_urn_component(value: str, *, safe: str) -> bool:
    if not value:
        return False
    try:
        decoded = unquote_to_bytes(value).decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return False
    if not decoded:
        return False
    if any(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in decoded
    ):
        return False
    if any(character in ",()" for character in decoded):
        return False
    try:
        encoded = quote(decoded, safe=safe, encoding="utf-8", errors="strict")
    except (UnicodeEncodeError, ValueError):
        return False
    return encoded == value
