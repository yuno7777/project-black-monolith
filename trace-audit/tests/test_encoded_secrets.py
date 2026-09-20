"""Encoded secret spans must be withheld before any streaming fragment escapes."""

import base64

import pytest
from src.pii_scanner import scan
from src.stream_proxy import PiiStreamBuffer

SECRET = "AKIAIOSFODNN7EXAMPLE"


def representations(value):
    raw = value.encode()
    return [
        base64.b64encode(raw).decode(),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
        raw.hex(),
        "0x" + raw.hex(),
        "".join(f"%{b:02X}" for b in raw),
        "AKIA" + "".join(f"%{b:02x}" for b in raw[4:]),
    ]


@pytest.mark.parametrize("encoded", representations(SECRET))
@pytest.mark.parametrize("width", [1, 2, 3, 7, 16, 64])
def test_encoded_fragment_redaction(encoded, width):
    text = "Reference: " + encoded + " done."
    buffer = PiiStreamBuffer()
    emitted = ""
    for start in range(0, len(text), width):
        drain = buffer.push(text[start : start + width], None)
        emitted += "".join(item.token for item in drain.outputs)
        assert encoded not in emitted
    emitted += "".join(item.token for item in buffer.finish().outputs)
    assert encoded not in emitted
    assert "[REDACTED:" in emitted
    assert emitted.endswith(" done.")


@pytest.mark.parametrize("encoded", representations("ordinary reference text"))
def test_benign_encoded_text_survives(encoded):
    assert scan(encoded) == []
    buffer = PiiStreamBuffer()
    outputs = []
    for char in encoded:
        outputs.extend(t.token for t in buffer.push(char, None).outputs)
    outputs.extend(t.token for t in buffer.finish().outputs)
    assert "".join(outputs) == encoded


@pytest.mark.parametrize(
    "encode", [lambda s: base64.b64encode(s.encode()).decode(), lambda s: s.encode().hex()]
)
def test_entire_encoded_atom_redacted_with_surrounding_decoded_text(encode):
    atom = encode("before " + SECRET + " after")
    matches = scan("X " + atom + " Y")
    assert any(m.start == 2 and m.end == 2 + len(atom) for m in matches)


def test_malformed_and_large_atoms_are_bounded():
    assert scan("%ZZ" * 3000) == []
    assert scan("A" * 10000) == []


def test_benign_prose_releases_before_old_512_character_window():
    buffer = PiiStreamBuffer()
    emitted = []
    text = "ordinary garden advice " * 20
    first_release = None
    for index, char in enumerate(text):
        drain = buffer.push(char, None)
        if drain.outputs and first_release is None:
            first_release = index + 1
        emitted.extend(t.token for t in drain.outputs)
    emitted.extend(t.token for t in buffer.finish().outputs)
    assert first_release is not None and first_release <= 280
    assert "".join(emitted) == text


@pytest.mark.parametrize("encoded", representations(SECRET))
@pytest.mark.parametrize("prefix_size", [200, 250, 255, 256, 280, 500, 512])
def test_encoded_secret_crossing_release_boundary(encoded, prefix_size):
    buffer = PiiStreamBuffer()
    text = ("safe " * 110)[:prefix_size] + " " + encoded + " done"
    output = []
    for char in text:
        output.extend(t.token for t in buffer.push(char, None).outputs)
    output.extend(t.token for t in buffer.finish().outputs)
    assert encoded not in "".join(output)
    assert "[REDACTED:" in "".join(output)
