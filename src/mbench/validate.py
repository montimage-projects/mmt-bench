"""``mbench validate``: check a record for completeness.

It checks sut.json records (#4) against the committed JSON Schema
(``src/mbench/schemas/sut.schema.json``) and re-computes their ``sut_hash``,
and the corpus manifest (#7, ``corpus/manifest.yaml``) against
``src/mbench/schemas/corpus-manifest.schema.json``. Campaign files are added
by #8.

Every problem is reported by the dotted path of the field, for example
``missing field: host.cpu.core_types[0].governor``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from mbench import sut

SUT_SCHEMA = "sut.schema.json"
MANIFEST_SCHEMA = "corpus-manifest.schema.json"


@cache
def schema(name: str = SUT_SCHEMA) -> dict[str, Any]:
    """A committed JSON Schema, from the installed package."""
    text = files("mbench").joinpath("schemas", name).read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


def format_path(parts: Iterator[str | int] | list[str | int]) -> str:
    out = ""
    for part in parts:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}" if out else str(part)
    return out or "(record)"


_REQUIRED = re.compile(r"^'(.+)' is a required property$")


def _leaf_errors(error: ValidationError) -> Iterator[ValidationError]:
    """The errors that name a field, below the ``anyOf`` value-or-marker choices.

    Every optional-value field is ``anyOf: [value schema, unavailable marker]``.
    When it fails, the useful error is the one from the value branch (index 0),
    unless the instance is shaped like a marker, when it is the marker branch.
    """
    if error.validator in {"anyOf", "oneOf"} and error.context:
        instance = error.instance
        marker_like = isinstance(instance, dict) and "unavailable" in instance
        branch = 1 if marker_like else 0
        chosen = [e for e in error.context if e.relative_schema_path[0] == branch]
        if chosen:
            for child in chosen:
                yield from _leaf_errors(child)
            return
    yield error


def describe(error: ValidationError) -> str:
    """One error, naming the field."""
    path = list(error.absolute_path)
    if (
        error.validator == "enum"
        and path
        and path[-1] == "unavailable"
        and error.instance in sut.UNAVAILABLE_KINDS
    ):
        # A known marker kind the field does not accept (an identity field
        # holding an ``error`` marker): the field must hold a value.
        field_path = format_path(path[:-1])
        return f"{field_path}: must hold a value here, not an unavailable marker ({error.instance})"
    if sut.is_unavailable(error.instance):
        kind = error.instance["unavailable"]
        return f"{format_path(path)}: must hold a value here, not an unavailable marker ({kind})"
    if error.validator == "required":
        m = _REQUIRED.match(error.message)
        if m:
            return f"missing field: {format_path([*path, m.group(1)])}"
    return f"{format_path(path)}: {error.message}"


def sut_errors(record: Any) -> list[str]:
    """Every reason ``record`` is not a complete sut.json record; empty if it is."""
    validator = Draft202012Validator(schema())
    errors = sorted(
        {describe(leaf) for error in validator.iter_errors(record) for leaf in _leaf_errors(error)}
    )
    if not errors and isinstance(record, dict):
        expected = sut.sut_hash(record)
        if record.get("sut_hash") != expected:
            errors.append(
                f"sut_hash: {record.get('sut_hash')} does not match the record ({expected})"
            )
    return errors


def manifest_errors(manifest: Any) -> list[str]:
    """Every reason ``manifest`` is not a valid corpus manifest; empty if it is.

    Beyond the schema: labels and paths are unique, and a generated entry's
    packet count and average packet size match its generator parameters.
    """
    validator = Draft202012Validator(schema(MANIFEST_SCHEMA))
    errors = sorted(
        {
            describe(leaf)
            for error in validator.iter_errors(manifest)
            for leaf in _leaf_errors(error)
        }
    )
    if errors or not isinstance(manifest, dict):
        return errors
    first: dict[tuple[str, object], int] = {}
    for i, entry in enumerate(manifest["entries"]):
        for key in ("label", "path"):
            seen = first.setdefault((key, entry[key]), i)
            if seen != i:
                errors.append(
                    f"entries[{i}].{key}: duplicate {entry[key]!r} (also entries[{seen}])"
                )
        gen = entry.get("generator")
        if gen is not None:
            for key, expected in (
                ("packets", gen["packets"]),
                ("avg_packet_bytes", gen["frame_bytes"]),
            ):
                if entry[key] != expected:
                    errors.append(
                        f"entries[{i}].{key}: {entry[key]} "
                        f"does not match its generator ({expected})"
                    )
    return errors


@dataclass
class Report:
    """The outcome of validating one file."""

    path: str
    kind: str
    errors: list[str] = field(default_factory=list)
    fields: int = 0
    unavailable: list[tuple[str, str, str]] = field(default_factory=list)
    scope: str = ""
    #: What a valid record of a kind other than ``sut`` holds, in a few words.
    summary: str = ""

    @property
    def ok(self) -> bool:
        return not self.errors


class UnsupportedRecord(ValueError):
    """The file is not a kind of record ``mbench validate`` checks yet."""


class UnreadableRecord(ValueError):
    """The file cannot be read as text (it is not UTF-8)."""


def validate_file(path: str | Path) -> Report:
    """Validate one file.

    Raises :class:`OSError`, :class:`UnreadableRecord`, :class:`UnsupportedRecord`.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise UnreadableRecord(
            f"{p}: unreadable: not UTF-8 text ({exc.reason} at byte {exc.start})"
        ) from None
    if p.suffix.lower() in {".yaml", ".yml"}:
        return _validate_yaml(p, text)
    try:
        record = json.loads(text)
    except ValueError as exc:
        return Report(str(p), "json", [f"not valid JSON: {exc}"])
    if not (isinstance(record, dict) and ("sut_hash" in record or "schema_version" in record)):
        raise UnsupportedRecord(
            f"{p}: not a sut.json record (no schema_version or sut_hash); "
            "mbench validate checks sut.json and corpus/manifest.yaml for now (campaigns: #8)"
        )
    report = Report(str(p), "sut", sut_errors(record), scope=str(record.get("scope", "")))
    report.fields = sut.field_count(record)
    report.unavailable = sut.unavailable_fields(record)
    return report


def is_manifest(path: Path, data: Any) -> bool:
    """A file named ``manifest.yaml``, or a YAML mapping with ``entries``."""
    return path.stem == "manifest" or (isinstance(data, dict) and "entries" in data)


def _validate_yaml(p: Path, text: str) -> Report:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return Report(str(p), "yaml", [f"not valid YAML: {exc}"])
    if not is_manifest(p, data):
        raise UnsupportedRecord(
            f"{p}: not a corpus manifest (no entries); campaign files are not checked yet (#8)"
        )
    report = Report(str(p), "corpus manifest", manifest_errors(data))
    if report.ok:
        entries = data["entries"]
        local = sum(1 for e in entries if e["local_only"])
        report.summary = f"{len(entries)} entries, {local} local-only"
    return report
