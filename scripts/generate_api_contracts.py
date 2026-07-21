"""Export the API OpenAPI document and deterministic browser compile-time types."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OPENAPI_PATH = ROOT / "docs" / "api" / "openapi.json"
TYPESCRIPT_PATH = ROOT / "apps" / "web" / "src" / "api" / "schema.generated.ts"


class ContractGenerationError(RuntimeError):
    """Raised instead of weakening an unsupported schema to an unsafe fallback type."""


def _openapi_document() -> dict[str, Any]:
    """Build the schema under a deterministic, local-only process configuration."""
    environment_keys = {
        "AQT_ENVIRONMENT": "local",
        "AQT_DATABASE_URL": "sqlite+pysqlite:///:memory:",
        "AQT_LOCAL_AUTH_ENABLED": "true",
        "AQT_SESSION_SECRET": "local-contract-generation-only",
    }
    previous = {key: os.environ.get(key) for key in environment_keys}
    os.environ.update(environment_keys)
    try:
        # Importing the composition root constructs its module-level ASGI app. The
        # temporary environment above keeps that import local and side-effect-free.
        from apps.api.config import Settings
        from apps.api.main import create_app

        return create_app(Settings()).openapi()
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _schema_ref(reference: str) -> str:
    prefix = "#/components/schemas/"
    if not reference.startswith(prefix):
        raise ContractGenerationError(f"unsupported JSON Schema reference: {reference}")
    name = reference.removeprefix(prefix)
    return f'components["schemas"][{json.dumps(name)}]'


def _schema_type(schema: dict[str, Any], level: int = 0) -> str:
    if reference := schema.get("$ref"):
        if not isinstance(reference, str):
            raise ContractGenerationError("JSON Schema $ref must be a string")
        return _schema_ref(reference)

    if "enum" in schema:
        values = schema["enum"]
        if not isinstance(values, list) or not values:
            raise ContractGenerationError("JSON Schema enum must be a non-empty list")
        return " | ".join(json.dumps(value) for value in values)

    for keyword, operator in (("anyOf", " | "), ("oneOf", " | "), ("allOf", " & ")):
        if keyword in schema:
            branches = schema[keyword]
            if not isinstance(branches, list) or not branches:
                raise ContractGenerationError(f"JSON Schema {keyword} must be a non-empty list")
            return operator.join(
                f"({_schema_type(_require_schema(branch, keyword), level)})" for branch in branches
            )

    schema_type = schema.get("type")
    if schema_type == "string":
        return "string"
    if schema_type in {"integer", "number"}:
        return "number"
    if schema_type == "boolean":
        return "boolean"
    if schema_type == "null":
        return "null"
    if schema_type == "array":
        items = _require_schema(schema.get("items"), "array items")
        return f"Array<{_schema_type(items, level)}>"
    if schema_type == "object":
        return _object_type(schema, level)
    if schema_type is None and set(schema).issubset(
        {"title", "description", "default", "examples"}
    ):
        # OpenAPI uses an unconstrained schema for values such as Pydantic's
        # validation-error input.  Preserve the trust boundary in TypeScript by
        # requiring narrowing from ``unknown`` rather than fabricating a type.
        return "unknown"

    raise ContractGenerationError(
        f"unsupported JSON Schema shape: {json.dumps(schema, sort_keys=True)}"
    )


def _require_schema(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractGenerationError(f"{context} must contain a JSON Schema object")
    return value


def _object_type(schema: dict[str, Any], level: int) -> str:
    properties_value = schema.get("properties", {})
    if not isinstance(properties_value, dict):
        raise ContractGenerationError("object properties must be a mapping")
    properties: dict[str, Any] = properties_value

    required_value = schema.get("required", [])
    if not isinstance(required_value, list) or not all(
        isinstance(name, str) for name in required_value
    ):
        raise ContractGenerationError("object required must be a list of property names")
    required = set(required_value)

    additional = schema.get("additionalProperties")
    if not properties and additional is None:
        # In OpenAPI, an object schema without declared properties or an
        # additionalProperties constraint is an unconstrained JSON object.
        # Emit an explicit record instead of ``{}``, whose TypeScript meaning
        # includes every non-nullish primitive and is rejected by our linter.
        return "Record<string, unknown>"

    lines = ["{"]
    child_indent = "  " * (level + 1)
    for name in sorted(properties):
        property_schema = _require_schema(properties[name], f"property {name}")
        optional = "" if name in required else "?"
        lines.append(
            f"{child_indent}{json.dumps(name)}{optional}: "
            f"{_schema_type(property_schema, level + 1)};"
        )

    if additional is True:
        raise ContractGenerationError(
            "untyped additionalProperties is unsupported; publish an explicit value schema"
        )
    if isinstance(additional, dict):
        lines.append(f"{child_indent}[key: string]: {_schema_type(additional, level + 1)};")
    elif additional not in {None, False}:
        raise ContractGenerationError("additionalProperties must be a schema or boolean")

    lines.append(f"{'  ' * level}}}")
    return "\n".join(lines)


def _typescript_contract(document: dict[str, Any]) -> str:
    components = document.get("components")
    if not isinstance(components, dict):
        raise ContractGenerationError("OpenAPI components are missing")
    schemas_value = components.get("schemas")
    if not isinstance(schemas_value, dict):
        raise ContractGenerationError("OpenAPI component schemas are missing")

    lines = [
        "/**",
        " * AUTO-GENERATED by scripts/generate_api_contracts.py.",
        " * Source: docs/api/openapi.json",
        " * These are compile-time wire types; they do not perform runtime validation.",
        " */",
        "",
        "export interface components {",
        "  schemas: {",
    ]
    for name in sorted(schemas_value):
        schema = _require_schema(schemas_value[name], f"component schema {name}")
        lines.append(f"    {json.dumps(name)}: {_schema_type(schema, 2)};")
    lines.extend(["  }", "}", "", "export interface paths {"])

    paths_value = document.get("paths")
    if not isinstance(paths_value, dict):
        raise ContractGenerationError("OpenAPI paths are missing")
    for path in sorted(paths_value):
        path_item = paths_value[path]
        if not isinstance(path_item, dict):
            raise ContractGenerationError(f"OpenAPI path item {path} must be an object")
        lines.extend([f"  {json.dumps(path)}: {{"])
        for method in sorted(path_item):
            if method not in {"delete", "get", "patch", "post", "put"}:
                continue
            operation = path_item[method]
            if not isinstance(operation, dict):
                raise ContractGenerationError(f"OpenAPI operation {method} {path} is invalid")
            responses = operation.get("responses")
            if not isinstance(responses, dict):
                raise ContractGenerationError(f"OpenAPI operation {method} {path} has no responses")
            lines.extend([f"    {method}: {{", "      responses: {"])
            for response_code in sorted(responses):
                response = responses[response_code]
                if not isinstance(response, dict):
                    raise ContractGenerationError(
                        f"OpenAPI response {method} {path} {response_code} is invalid"
                    )
                content = response.get("content")
                if not isinstance(content, dict) or not content:
                    raise ContractGenerationError(
                        f"OpenAPI response {method} {path} {response_code} has no content schema"
                    )
                lines.extend([f"        {json.dumps(response_code)}: {{", "          content: {"])
                for media_type in sorted(content):
                    media = content[media_type]
                    if not isinstance(media, dict):
                        raise ContractGenerationError(
                            f"OpenAPI media type {method} {path} {media_type} is invalid"
                        )
                    schema = _require_schema(media.get("schema"), f"media type {media_type}")
                    lines.append(
                        f"            {json.dumps(media_type)}: {_schema_type(schema, 6)};"
                    )
                lines.extend(["          }", "        }"])
            lines.extend(["      }", "    }"])
        lines.append("  }")
    lines.extend(["}", ""])
    return "\n".join(lines)


def _artifacts() -> dict[Path, str]:
    document = _openapi_document()
    return {
        OPENAPI_PATH: json.dumps(document, indent=2, sort_keys=True) + "\n",
        TYPESCRIPT_PATH: _typescript_contract(document),
    }


def _check(artifacts: dict[Path, str]) -> int:
    stale = [
        path.relative_to(ROOT)
        for path, expected in artifacts.items()
        if not path.exists() or path.read_text() != expected
    ]
    if not stale:
        print("API contract artifacts are current.")
        return 0
    print("API contract artifacts are stale; run `make api-contracts`:")
    for path in stale:
        print(f"  {path}")
    return 1


def _write(artifacts: dict[Path, str]) -> None:
    for path, content in artifacts.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        print(f"wrote {path.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail without writing if checked-in artifacts differ from the API schema",
    )
    args = parser.parse_args()
    artifacts = _artifacts()
    if args.check:
        return _check(artifacts)
    _write(artifacts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
