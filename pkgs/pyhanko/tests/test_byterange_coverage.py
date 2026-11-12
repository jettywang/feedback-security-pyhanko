"""
Regression tests for ``/ByteRange`` coverage evaluation.

These tests sign an in-memory PDF and then apply small byte-level
modifications to the result: overlapping byte ranges, extra uncovered
bytes, a relocated signature value gap, and a legitimate appended
revision. For every sample, both the cryptographic validation result
and the coverage judgment are recorded, since backends need to
distinguish "the signature itself is valid" from "the current file is
fully covered by the signature".
"""

import asyncio
import binascii
import re
from datetime import UTC, datetime
from io import BytesIO

import pytest
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.general import byte_range_digest
from pyhanko.sign.signers.pdf_cms import PdfCMSSignedAttributes
from pyhanko.sign.validation import (
    DocumentSecurityStore,
    SignatureCoverageLevel,
    validate_pdf_signature,
)
from pyhanko_testing_commons.test_data.samples import MINIMAL
from pyhanko_testing_commons.test_utils.signing_commons import (
    SELF_SIGN,
    simple_v_context,
)

BYTE_RANGE_PATTERN = re.compile(rb'/ByteRange\s*\[')
CONTENTS_PATTERN = re.compile(rb'/Contents\s*<')


def _sign_minimal() -> bytes:
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=SELF_SIGN
    )
    return out.getvalue()


def _byte_range_value_span(data: bytes) -> tuple[int, int]:
    match = BYTE_RANGE_PATTERN.search(data)
    assert match is not None
    start = match.end()
    end = data.index(b']', start)
    return start, end


def _read_byte_range(data: bytes) -> list[int]:
    start, end = _byte_range_value_span(data)
    return [int(tok) for tok in data[start:end].split()]


def _rewrite_byte_range(data: bytearray, new_byte_range) -> None:
    # the /ByteRange array is written into a fixed-width placeholder,
    # so replacement values can be padded with whitespace
    start, end = _byte_range_value_span(data)
    capacity = end - start
    new_value = ' '.join(str(x) for x in new_byte_range).encode()
    assert len(new_value) <= capacity
    data[start:end] = new_value + b' ' * (capacity - len(new_value))


def _contents_hex_span(data: bytes) -> tuple[int, int]:
    # the /Contents of the signature is the last hex string /Contents
    # preceding the /ByteRange array
    br_start, _ = _byte_range_value_span(data)
    matches = list(CONTENTS_PATTERN.finditer(data, 0, br_start))
    assert matches
    start = matches[-1].end()
    end = data.index(b'>', start)
    return start, end


def _resign(data: bytearray, byte_range, md_algorithm='sha256') -> None:
    """
    Recompute the digest over the (tampered) byte range and re-sign it,
    writing the new CMS into the existing ``/Contents`` placeholder.
    This keeps the file length unchanged, and produces a file that is
    cryptographically self-consistent in spite of its anomalous layout.
    """
    _, digest = byte_range_digest(
        BytesIO(bytes(data)), byte_range=byte_range, md_algorithm=md_algorithm
    )
    new_cms = asyncio.run(
        SELF_SIGN.async_sign(
            digest,
            md_algorithm,
            use_pades=False,
            signed_attr_settings=PdfCMSSignedAttributes(
                signing_time=datetime(2020, 11, 1, tzinfo=UTC)
            ),
        )
    )
    der_bytes = new_cms if isinstance(new_cms, bytes) else new_cms.dump()
    start, end = _contents_hex_span(data)
    capacity = end - start
    hex_cms = binascii.hexlify(der_bytes).upper()
    assert len(hex_cms) <= capacity
    data[start:end] = hex_cms + b'0' * (capacity - len(hex_cms))


def _sample_untouched() -> bytes:
    return _sign_minimal()


def _sample_overlapping_ranges() -> bytes:
    # the second range reaches back into the first one, and everything
    # past the start of /Contents is left out of the digest entirely
    data = bytearray(_sign_minimal())
    _, len1, _, _ = _read_byte_range(data)
    new_byte_range = [0, len1, len1 - 64, 64]
    _rewrite_byte_range(data, new_byte_range)
    _resign(data, new_byte_range)
    return bytes(data)


def _sample_uncovered_tail() -> bytes:
    # shave some bytes off the end of the signed region, so part of the
    # signed revision (including the xref table trailer) is not covered
    data = bytearray(_sign_minimal())
    _, len1, start2, len2 = _read_byte_range(data)
    new_byte_range = [0, len1, start2, len2 - 32]
    _rewrite_byte_range(data, new_byte_range)
    _resign(data, new_byte_range)
    return bytes(data)


def _sample_gap_boundaries_widened() -> bytes:
    # move the gap boundaries outwards, so the uncovered region contains
    # bytes that do not belong to the /Contents value
    data = bytearray(_sign_minimal())
    _, len1, start2, len2 = _read_byte_range(data)
    new_byte_range = [0, len1 - 16, start2 + 16, len2 - 16]
    _rewrite_byte_range(data, new_byte_range)
    _resign(data, new_byte_range)
    return bytes(data)


def _sample_gap_shifted() -> bytes:
    # shift the entire gap by a few bytes while preserving its length;
    # the resulting file is *not* re-signed, so the digest no longer
    # matches, but the coverage check must still refuse to treat the
    # gap as the signature contents
    data = bytearray(_sign_minimal())
    _, len1, start2, len2 = _read_byte_range(data)
    _rewrite_byte_range(data, [0, len1 + 16, start2 + 16, len2 - 16])
    return bytes(data)


def _sample_appended_revision() -> bytes:
    out = BytesIO(_sign_minimal())
    DocumentSecurityStore.add_dss(
        out, sig_contents=None, certs=(SELF_SIGN.signing_cert,)
    )
    return out.getvalue()


SAMPLES = {
    'untouched': _sample_untouched,
    'overlapping-ranges': _sample_overlapping_ranges,
    'uncovered-tail': _sample_uncovered_tail,
    'gap-boundaries-widened': _sample_gap_boundaries_widened,
    'gap-shifted': _sample_gap_shifted,
    'appended-revision': _sample_appended_revision,
}

# expected (intact, valid, coverage) per sample; this matrix records both
# the cryptographic validation result and the coverage judgment, which
# are orthogonal: a signature can be cryptographically sound without
# covering the entire current file, and vice versa
EXPECTATIONS = {
    'untouched': (True, True, SignatureCoverageLevel.ENTIRE_FILE),
    'overlapping-ranges': (True, True, SignatureCoverageLevel.UNCLEAR),
    'uncovered-tail': (
        True,
        True,
        SignatureCoverageLevel.CONTIGUOUS_BLOCK_FROM_START,
    ),
    'gap-boundaries-widened': (True, True, SignatureCoverageLevel.UNCLEAR),
    # the shifted gap invalidates the digest, but the CMS itself is
    # still mathematically valid
    'gap-shifted': (False, True, SignatureCoverageLevel.UNCLEAR),
    'appended-revision': (True, True, SignatureCoverageLevel.ENTIRE_REVISION),
}


def _evaluate(data: bytes):
    reader = PdfFileReader(BytesIO(data))
    emb_sig = reader.embedded_signatures[0]
    status = validate_pdf_signature(emb_sig, simple_v_context())
    return status


@pytest.mark.parametrize('sample_name', list(SAMPLES))
def test_byte_range_coverage_sample(sample_name):
    data = SAMPLES[sample_name]()
    expected_intact, expected_valid, expected_coverage = EXPECTATIONS[
        sample_name
    ]
    status = _evaluate(data)
    assert status.intact == expected_intact
    assert status.valid == expected_valid
    assert status.coverage == expected_coverage
    # none of the anomalous layouts may pass the bottom-line check
    if expected_coverage in (
        SignatureCoverageLevel.UNCLEAR,
        SignatureCoverageLevel.CONTIGUOUS_BLOCK_FROM_START,
    ):
        assert not status.bottom_line
        if status.intact:
            assert 'NONSTANDARD_COVERAGE' in status.summary()


def test_coverage_report():
    # record the cryptographic and coverage judgments for all samples
    lines = []
    for sample_name, factory in SAMPLES.items():
        status = _evaluate(factory())
        expected_intact, expected_valid, expected_coverage = EXPECTATIONS[
            sample_name
        ]
        assert status.intact == expected_intact
        assert status.valid == expected_valid
        assert status.coverage == expected_coverage
        lines.append(
            f'{sample_name:25s} intact={status.intact!s:5s} '
            f'valid={status.valid!s:5s} coverage={status.coverage.name}'
        )
    report = '\n'.join(lines)
    print(f'\n{report}')
