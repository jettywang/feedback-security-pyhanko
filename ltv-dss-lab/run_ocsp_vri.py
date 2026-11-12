"""OCSP vs CRL, and correct vs wrong VRI key (global-pool semantics)."""
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

CHECK = datetime.datetime(2021, 6, 5, tzinfo=datetime.UTC)


async def check(data, label):
    print(f"\n#### {label} ####")
    print(L.revision_map(data))
    with freeze_time(CHECK):
        r = PdfFileReader(BytesIO(data))
        res = await ades.ades_lta_validation(
            r.embedded_signatures[0], pdf_validation_spec=P.lta_spec())
    print(f"  -> {res.ades_subindic.name} (best {res.best_signature_time:%Y-%m-%d})")
    return res.ades_subindic.name


async def main():
    chain = [P.ROOT_CERT, P.INTERM_CERT, P.TSA_CERT]
    ocsp = P.signer_ocsp(P.DSS1_TIME)

    # E: OCSP for the leaf + root CRL for the CA/TSA side, all before the TS
    e = await L.sign_first(P.SIGN_TIME, P)
    e = await L.add_dss(e, P.DSS1_TIME, P, certs=chain,
                        crls=[P.root_crl(P.DSS1_TIME)], ocsps=[ocsp],
                        vri_target='none')
    e = await L.add_dts(e, P.DTS1_TIME, P, P.tsa1_fixed(P.DTS1_TIME))
    Path(P.ARTIFACT_DIR, "matrix_E_ocsp.pdf").write_bytes(e)
    re = await check(e, "E: leaf OCSP + root CRL, all before TS")

    # F: correct VRI key (points at the user signature), pools before TS
    f = await L.sign_first(P.SIGN_TIME, P)
    f = await L.add_dss(f, P.DSS1_TIME, P, certs=chain,
                        crls=[P.interm_crl(P.DSS1_TIME),
                              P.root_crl(P.DSS1_TIME)],
                        vri_target='sig')
    f = await L.add_dts(f, P.DTS1_TIME, P, P.tsa1_fixed(P.DTS1_TIME))
    Path(P.ARTIFACT_DIR, "matrix_F_correct_vri.pdf").write_bytes(f)
    rf = await check(f, "F: pools before TS + CORRECT VRI key")

    print("\n==== SUMMARY ====")
    print("E OCSP-based :", re)
    print("F correct-VRI:", rf)


asyncio.run(main())
