"""Can late revinfo be salvaged? Only by a later timestamp covering it."""
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

SALVAGE_DSS = datetime.datetime(2021, 9, 1, tzinfo=datetime.UTC)
SALVAGE_TS = datetime.datetime(2021, 9, 5, tzinfo=datetime.UTC)
CHECK = datetime.datetime(2021, 10, 1, tzinfo=datetime.UTC)


async def main():
    chain = [P.ROOT_CERT, P.INTERM_CERT, P.TSA_CERT]

    # B again: DTS first, late DSS, no covering timestamp
    b = await L.sign_first(P.SIGN_TIME, P)
    b = await L.add_dts(b, P.DTS1_TIME, P, P.tsa1_fixed(P.DTS1_TIME))
    b = await L.add_dss(b, SALVAGE_DSS, P, certs=chain,
                        crls=[P.interm_crl(SALVAGE_DSS),
                              P.root_crl(SALVAGE_DSS)],
                        vri_target='none')

    # G: same late DSS, but now add a SECOND document timestamp that covers it
    g = await L.add_dts(b, SALVAGE_TS, P, P.tsa1_fixed(SALVAGE_TS))
    Path(P.ARTIFACT_DIR, "matrix_G_salvaged.pdf").write_bytes(g)

    print("#### G: late DSS salvaged by a subsequent document timestamp ####")
    print(L.revision_map(g))
    print("POE index:")
    print(L.poe_map(g))
    for data, tag in ((b, "B (late DSS, no cover)"), (g, "G (late DSS + DTS2)")):
        with freeze_time(CHECK):
            r = PdfFileReader(BytesIO(data))
            res = await ades.ades_lta_validation(
                r.embedded_signatures[0], pdf_validation_spec=P.lta_spec())
        print(f"{tag:30s} -> {res.ades_subindic.name:12s} "
              f"best={res.best_signature_time:%Y-%m-%d}")


asyncio.run(main())
