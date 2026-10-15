"""Strict JSON and cross-field agreement; fixtures never grant live authority."""

import pytest

from .collection_decode_support import DecodeFailure, strict_decode
from .test_collection_contracts import ROOT, load_object


def test_every_case_passes_or_fails_at_the_declared_layer() -> None:
    for case in load_object(ROOT / "fixtures/collection-cases.json")["cases"]:
        name = case["schema"].rsplit("/", 1)[1].removesuffix(".schema.json")
        raw = (ROOT / case["file"]).read_bytes()
        if case["valid"]:
            assert strict_decode(name, raw) == load_object(ROOT / case["file"])
        else:
            with pytest.raises(DecodeFailure) as error:
                strict_decode(name, raw)
            if case["stage"] == "decode":
                assert str(error.value) == case["reason"], case["file"]


@pytest.mark.parametrize(
    "raw,reason",
    [(b"\xff", "Json"), (b" " * 65537, "Size"), (b"[" * 16 + b"0" + b"]" * 16, "Schema")],
)
def test_raw_encoding_size_and_depth_edges(raw: bytes, reason: str) -> None:
    with pytest.raises(DecodeFailure, match=f"^{reason}$"):
        strict_decode("types", raw)


def test_decode_error_does_not_include_input() -> None:
    with pytest.raises(DecodeFailure) as error:
        strict_decode("types", b'{"schema_version":"1.0.0","private-canary":"secret"}')
    assert str(error.value) == "Schema"
