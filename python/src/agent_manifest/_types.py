"""Custom scalar types for the Agent Manifest SDK."""
from __future__ import annotations

import re
from typing import Any

from pydantic import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema


class ManifestId(str):
    """UUID v7 — time-ordered per RFC 9562.

    Format: xxxxxxxx-xxxx-7xxx-[89ab]xxx-xxxxxxxxxxxx
    The version nibble (position 14 in the hex string) MUST be '7'.
    The variant nibble (position 19) MUST be one of [89ab].
    """

    _PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.to_string_ser_schema(),
        )

    @classmethod
    def _validate(cls, v: Any) -> "ManifestId":
        if not isinstance(v, str):
            raise ValueError(f"ManifestId must be a string, got {type(v).__name__}")
        if not cls._PATTERN.match(v):
            raise ValueError(
                f"'{v}' is not a valid UUID v7. "
                "Expected format: xxxxxxxx-xxxx-7xxx-[89ab]xxx-xxxxxxxxxxxx"
            )
        return cls(v)


class HashValue(str):
    """Cryptographic hash with algorithm prefix.

    Valid formats:
      sha256:<64 lowercase hex chars>
      shake256:<64 lowercase hex chars>  (256-bit output, per RFC 8785 / FIPS 202)
    """

    _PATTERN = re.compile(r"^(sha256|shake256):[0-9a-f]{64}$")

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.to_string_ser_schema(),
        )

    @classmethod
    def _validate(cls, v: Any) -> "HashValue":
        if not isinstance(v, str):
            raise ValueError(f"HashValue must be a string, got {type(v).__name__}")
        if not cls._PATTERN.match(v):
            prefix = v.split(":")[0] if ":" in v else v[:10]
            raise ValueError(
                f"Invalid hash value (prefix='{prefix}'). "
                "Expected sha256:<64-hex> or shake256:<64-hex>"
            )
        return cls(v)

    @property
    def algorithm(self) -> str:
        return self.split(":")[0]

    @property
    def hex_digest(self) -> str:
        return self.split(":")[1]
