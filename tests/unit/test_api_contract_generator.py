from scripts.generate_api_contracts import _schema_type


def test_unconstrained_json_object_generates_lint_safe_record() -> None:
    assert _schema_type({"type": "object", "title": "Context"}) == ("Record<string, unknown>")


def test_unconstrained_json_value_requires_typescript_narrowing() -> None:
    assert _schema_type({"title": "Input"}) == "unknown"
