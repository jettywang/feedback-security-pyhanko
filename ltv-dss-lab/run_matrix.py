"""Core matrix: effect of DSS material ordering relative to the DocTS.

Two validation instants are reported per scenario:
  * 2021-06-05: inside the embedded CRLs' validity window
  * 2025-06-01: signer leaf (signer1) has expired (2022), exercising the
    full AdES past-validation / time-slide path, while TSA1 is still valid
"""
import asyncio
import datetime
import sys
from io import BytesIO
from pathlib import Path

from freezegun import freeze_time

sys.path.insert(0, str(Path(__file__).parent))
import pki_common as P  # noqa: E402
import lab_lib as L  # noqa: E402

from pyhanko.pdf_utils.reader import PdfFileReader  # noqa: E402
from pyhanko.sign.validation import ades  # noqa: E402

IN_WINDOW = datetime.datetime(2021, 6, 5, tzinfo=datetime.UTC)
AFTER_EXPIRY = datetime.datetime(2025, 6, 1, tzinfo=datetime.UTC)


async def validate(data, label):
    print(f"\n########## {label} ##########")
    print(L.revision_map(data))
    print("POE index:")
    print(L.poe_map(data))
    rows = {}
    for check in (IN_WINDOW, AFTER_EXPIRY):
        with freeze_time(check):
            reader = PdfFileReader(BytesIO(data))
            result = await ades.ades_lta_validation(
                reader.embedded_signatures[0],
                pdf_validation_spec=P.lta_spec(),
            )
        er = (result.oldest_evidence_record_timestamp and
              result.oldest_evidence_record_timestamp.strftime("%Y-%m-%d"))
        rows[check.year] = result.ades_subindic.name
        print(f"  validate {check:%Y-%m-%d}: {result.ades_subindic.name:35s} "
              f"best={result.best_signature_time:%Y-%m-%d} ER={er}")
    return rows


async def main():
    chain_certs = [P.ROOT_CERT, P.INTERM_CERT, P.TSA_CERT]
    fresh_crls = [P.interm_crl(P.DSS1_TIME), P.root_crl(P.DSS1_TIME)]

    # A: complete DSS material in a revision BEFORE the document timestamp
    a = await L.sign_first(P.SIGN_TIME, P)
    a = await L.add_dss(a, P.DSS1_TIME, P, certs=chain_certs,
                        crls=fresh_crls, vri_target='none')
    a = await L.add_dts(a, P.DTS1_TIME, P, P.tsa1_fixed(P.DTS1_TIME))
    Path(P.ARTIFACT_DIR, "matrix_A_before.pdf").write_bytes(a)
    ra = await validate(a, "A: complete DSS BEFORE timestamp")

    # B: document timestamp first; revinfo only lands in a LATER revision
    b = await L.sign_first(P.SIGN_TIME, P)
    b = await L.add_dts(b, P.DTS1_TIME, P, P.tsa1_fixed(P.DTS1_TIME))
    b = await L.add_dss(b, P.LATE_DSS_TIME, P, certs=chain_certs,
                        crls=[P.interm_crl(P.LATE_DSS_TIME),
                              P.root_crl(P.LATE_DSS_TIME)],
                        vri_target='none')
    Path(P.ARTIFACT_DIR, "matrix_B_after.pdf").write_bytes(b)
    rb = await validate(b, "B: revinfo added only AFTER timestamp")

    # C: global pools complete before the TS, but the VRI key is attached to
    #    the document timestamp instead of the user signature
    c = await L.sign_first(P.SIGN_TIME, P)
    c = await L.add_dts(c, P.DTS1_TIME, P, P.tsa1_fixed(P.DTS1_TIME))
    c = await L.add_dss(c, P.DSS1_TIME, P, certs=chain_certs,
                        crls=fresh_crls, vri_target='dts')
    # NOTE: DSS content itself still sits in a revision after the DocTS here;
    # a second variant below puts pools first and only the VRI is wrong.
    Path(P.ARTIFACT_DIR, "matrix_C_wrong_vri.pdf").write_bytes(c)
    rc = await validate(c, "C: VRI key points at wrong signature record")

    # C2: pools BEFORE the timestamp (so POE is fine), but VRI key is wrong
    c2 = await L.sign_first(P.SIGN_TIME, P)
    c2 = await L.add_dss(c2, P.DSS1_TIME, P, certs=chain_certs,
                         crls=fresh_crls, vri_target='none')
    c2 = await L.add_dts(c2, P.DTS1_TIME, P, P.tsa1_fixed(P.DTS1_TIME))
    # post-TS revision that merely registers a bogus VRI over same data
    c2 = await L.add_dss(c2, P.LATE_DSS_TIME, P, certs=chain_certs,
                         crls=fresh_crls, vri_target='dts')
    Path(P.ARTIFACT_DIR, "matrix_C2_wrong_vri_pools_before.pdf").write_bytes(c2)
    rc2 = await validate(c2, "C2: pools before TS, wrong VRI key only")

    # D: signature + timestamp, no DSS at all
    d = await L.sign_first(P.SIGN_TIME, P)
    d = await L.add_dts(d, P.DTS1_TIME, P, P.tsa1_fixed(P.DTS1_TIME))
    Path(P.ARTIFACT_DIR, "matrix_D_no_dss.pdf").write_bytes(d)
    rd = await validate(d, "D: no DSS at all")

    print("\n================ SUMMARY ================")
    print(f"{'scenario':28s} {'2021 (in window)':20s} {'2025 (leaf expired)'}")
    for name, rows in (("A before-TS", ra), ("B after-TS", rb),
                       ("C wrong-VRI-late", rc),
                       ("C2 wrong-VRI-only", rc2), ("D no-DSS", rd)):
        print(f"{name:28s} {rows[2021]:20s} {rows[2025]}")


asyncio.run(main())
