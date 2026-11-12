"""Reusable building blocks and inspection helpers for the LTV lab."""
import hashlib
from io import BytesIO

from freezegun import freeze_time

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import HistoricalResolver, PdfFileReader
from pyhanko.sign import PdfTimeStamper, fields, signers
from pyhanko.sign.signers.pdf_signer import TimestampDSSContentSettings
from pyhanko.sign.validation.ades import (
    _build_prima_facie_poe_index_from_pdf_timestamps,
)
from pyhanko.sign.validation.dss import DocumentSecurityStore


def _reader(data):
    return PdfFileReader(BytesIO(data))


async def sign_first(at, pki, with_signature_ts=True):
    """Revision 1: PAdES signature with a signature timestamp, but no
    DSS and no document timestamp (those are added in later revisions)."""
    with freeze_time(at):
        writer = IncrementalPdfFileWriter(BytesIO(pki.minimal_pdf_bytes()))
        out = signers.async_sign_pdf(
            writer,
            signers.PdfSignatureMetadata(
                field_name='Sig1',
                validation_context=pki.offline_vc(),
                subfilter=fields.SigSeedSubFilter.PADES,
                use_pades_lta=False,
                embed_validation_info=False,
            ),
            signer=pki.FROM_CA,
            timestamper=(
                pki.tsa1_fixed(at) if with_signature_ts else None
            ),
        )
        return (await out).getvalue()


def _vri_identifier(reader, target):
    # target: 'sig' for the user signature, 'dts' for a document timestamp
    wanted = '/Sig' if target == 'sig' else '/DocTimeStamp'
    for sig in reader.embedded_signatures:
        if sig.sig_object_type == wanted:
            contents = sig.pkcs7_content.hex().encode('ascii')
            return DocumentSecurityStore.sig_content_identifier(contents)
    raise IndexError(f'no signature of type {wanted} present yet')


async def add_dss(data, at, pki, *, certs=(), crls=(), ocsps=(),
            vri_target='none'):
    """Append a revision that updates the DSS.

    vri_target:
        * 'sig'  -> VRI key computed from the user signature (correct record)
        * 'dts'  -> VRI key computed from a DocTimeStamp (wrong record)
        * 'none' -> no VRI, global DSS pools only
    """
    with freeze_time(at):
        reader = _reader(data)
        if vri_target == 'none':
            identifier = None
        else:
            identifier = _vri_identifier(reader, vri_target)
        writer = IncrementalPdfFileWriter.from_reader(reader)
        dss = DocumentSecurityStore.supply_dss_in_writer(
            writer,
            sig_contents=None,  # we register the VRI manually below
            certs=list(certs),
            crls=list(crls),
            ocsps=list(ocsps),
        )
        if identifier is not None:
            dss.register_vri(
                identifier,
                certs=list(certs),
                crls=list(crls),
                ocsps=list(ocsps),
            )
            dss.as_pdf_object()
        buf = BytesIO()
        writer.write(buf)
        return buf.getvalue()


async def add_dts(data, at, pki, timestamper):
    """Append a document timestamp revision (no automatic DSS update)."""
    with freeze_time(at):
        reader = _reader(data)
        writer = IncrementalPdfFileWriter.from_reader(reader)
        buf = BytesIO()
        await PdfTimeStamper(timestamper).async_timestamp_pdf(
                writer,
                md_algorithm='sha256',
                in_place=False,
                output=buf,
                validation_context=pki.offline_vc(),
                dss_settings=TimestampDSSContentSettings(include_vri=False),
            )
        return buf.getvalue()


def revision_map(data):
    """Show signatures and DSS material visible at each PDF revision."""
    reader = _reader(data)
    lines = []
    lines.append(f"total revisions: {reader.total_revisions}")
    for sig in reader.embedded_signatures:
        lines.append(
            f"  rev {sig.signed_revision}: {sig.sig_object_type} "
            f"(field {sig.field_name!r})"
        )
    for rev in range(1, reader.total_revisions + 1):
        hist = HistoricalResolver(reader, revision=rev)
        try:
            dss = DocumentSecurityStore.read_dss(hist)
        except Exception:
            lines.append(f"  rev {rev}: no DSS")
            continue
        vri = list(dss.vri_entries.keys()) if dss.vri_entries else []
        lines.append(
            f"  rev {rev}: DSS certs={len(dss.certs)} "
            f"crls={len(dss.crls)} ocsps={len(dss.ocsps)} vri={vri}"
        )
    return "\n".join(lines)


def poe_map(data):
    """Show which DSS objects each document timestamp proves existence for."""
    reader = _reader(data)
    poe_sets = _build_prima_facie_poe_index_from_pdf_timestamps(
        reader, include_content_ts=True, diff_policy=None
    )
    lines = []
    for poe in poe_sets:
        by_type = {}
        for item in poe.poes_implied:
            t = item.validation_object.object_type.name
            by_type[t] = by_type.get(t, 0) + 1
        lines.append(
            f"  DocTS at rev {poe.pdf_revision}, tst genTime "
            f"{poe.timestamp_dt:%Y-%m-%d}: POE objects={by_type}"
        )
    return "\n".join(lines) if lines else "  (no document/content timestamps)"


def dss_fingerprints(data):
    """SHA-256 of each DSS CRL/OCSP/cert, to trace material across revs."""
    reader = _reader(data)
    try:
        dss = DocumentSecurityStore.read_dss(reader)
    except Exception:
        return "no DSS"
    out = []
    for ref in dss.crls:
        raw = ref.get_object().read_data()
        out.append(("CRL ", hashlib.sha256(raw).hexdigest()[:16]))
    for ref in dss.ocsps:
        raw = ref.get_object().read_data()
        out.append(("OCSP", hashlib.sha256(raw).hexdigest()[:16]))
    for ref in dss.certs.values():
        raw = ref.get_object().read_data()
        out.append(("CERT", hashlib.sha256(raw).hexdigest()[:16]))
    return "\n".join(f"  {k} {v}" for k, v in out)
