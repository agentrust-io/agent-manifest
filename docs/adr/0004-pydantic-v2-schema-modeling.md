# ADR-0004: Pydantic v2 for schema modeling and validation in the Python SDK

**Status**: Accepted  
**Date**: 2026-05-15  
**Spec section**: Section 2.1 (Manifest Schema), Section 5.2 (SDK conformance)

## Context

The Python SDK needs a schema modeling layer that:

1. Maps the manifest JSON schema (defined in the spec) to Python objects
2. Validates fields at construction time, not silently at serialization
3. Produces canonical JSON output that matches what the spec requires for signing
4. Remains maintainable as the spec evolves

Several options exist in the Python ecosystem: Pydantic v2, dataclasses + marshmallow, attrs + cattrs, msgspec, and hand-written validation.

## Decision

Use **Pydantic v2** (`pydantic>=2.0`) as the sole schema and validation layer for all manifest models in the Python SDK.

Specifically:

- All manifest types are `pydantic.BaseModel` subclasses
- `model_dump(mode="json")` is used for serialization; `model_validate_json` / `model_validate` for deserialization
- `exclude_none=True` is enforced at the canonicalization layer, not inside Pydantic models
- Pydantic is a mandatory dependency, not optional

## Rationale

**Type safety without boilerplate.** Pydantic v2 generates a Rust-backed validator (pydantic-core) from Python type annotations. Fields are validated at `__init__` time — a manifest with a malformed `manifest_id` raises immediately, before any signing or serialization occurs.

**JSON round-trip fidelity.** `model_dump(mode="json")` converts datetime objects to ISO 8601 strings, enums to their string values, and nested models to dicts — exactly what RFC 8785 canonicalization requires. Hand-rolling this conversion is error-prone and was a source of interoperability bugs in the pre-Pydantic prototype.

**Schema evolution is cheap.** Adding or removing a field in the spec means adding or removing one line in the model. Pydantic's `Optional` fields with `default=None` map directly to the spec's optional field semantics.

**Ecosystem alignment.** FastAPI, which is used for the verification and CRL endpoints, is built on Pydantic. Using the same modeling layer means request/response types and manifest types share the same serialization semantics.

## Alternatives considered

**dataclasses + marshmallow**: Two libraries, two type annotation syntaxes, manual registration of nested schemas. The round-trip fidelity between marshmallow schemas and Python dataclasses requires explicit field mapping that duplicates the spec field list.

**attrs + cattrs**: Well-designed, but cattrs requires explicit converter registration for enums and datetimes. The spec has 15+ enum types and 8+ datetime fields — the converter boilerplate is larger than the equivalent Pydantic model.

**msgspec**: Faster than Pydantic for pure serialization, but no FastAPI integration and limited support for complex validation rules (e.g., `ManifestId` must be a UUID v7, not just a string). Custom validators in msgspec require more ceremony than Pydantic's `@field_validator`.

**Hand-written validation**: Used in the initial prototype. Abandoned after the third time a missing `isinstance` check produced a JSON encoding error at signing time rather than a clear validation error at construction.

## Consequences

- `pydantic>=2.0` is a hard dependency. This brings in `pydantic-core` (a Rust extension), which adds ~2 MB to the wheel and requires a binary wheel for each platform. Wheels are published for all major platforms on PyPI.
- Code that constructs manifest objects gets type-checked by mypy via pydantic's mypy plugin. This is required: `pyproject.toml` enables `[tool.mypy] plugins = ["pydantic.mypy"]`.
- Upgrading from Pydantic v1 is not possible — the SDK targets v2 only. The `model_dump` / `model_validate` API names are v2-specific.
- Future SDK ports (.NET, Go, Rust) must implement equivalent validation logic without Pydantic. The Python implementation serves as the reference for field constraints.

## References

- [Pydantic v2 documentation](https://docs.pydantic.dev/latest/)
- [pydantic-core (Rust backend)](https://github.com/pydantic/pydantic-core)
- Spec Section 2.1: Manifest JSON Schema definition
