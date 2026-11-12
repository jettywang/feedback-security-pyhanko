"""Offline PKI + time helpers for the DSS/LTV experiment.

Uses pyHanko's own certomancer test PKI (no network, no local HTTP server).
All wall-clock manipulation goes through freezegun, because certomancer's
CRL/OCSP builders and pyHanko's DummyTimeStamper read the current time.
"""
import datetime
import os

from freezegun import freeze_time
from certomancer.registry import ServiceLabel
from pyhanko_testing_commons.test_data.samples import MINIMAL_ONE_FIELD
from pyhanko_testing_commons.test_utils.signing_commons import (
    FROM_CA,
    INTERM_CERT,
    ROOT_CERT,
    TRUST_ROOTS,
    TSA_CERT,
    TSA2_CERT,
)
from pyhanko.sign import timestamps
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    FreshnessReqType,
    REQUIRE_REVINFO,
)
from pyhanko_certvalidator.registry import SimpleTrustManager
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec,
    RevocationInfoGatheringSpec,
    RevinfoOnlineFetchingRule,
    SignatureValidationSpec,
)

# --- experiment timeline (all UTC) ---------------------------------------
SIGN_TIME = datetime.datetime(2020, 11, 20, tzinfo=datetime.UTC)
DSS1_TIME = datetime.datetime(2021, 5, 25, tzinfo=datetime.UTC)
DTS1_TIME = datetime.datetime(2021, 6, 1, tzinfo=datetime.UTC)
LATE_DSS_TIME = datetime.datetime(2021, 9, 1, tzinfo=datetime.UTC)
DSS2_TIME = datetime.datetime(2028, 5, 25, tzinfo=datetime.UTC)
DTS2_TIME = datetime.datetime(2028, 6, 1, tzinfo=datetime.UTC)
FUTURE_TIME = datetime.datetime(2030, 11, 20, tzinfo=datetime.UTC)

ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), 'artifacts')


def offline_vc():
    """Validation context that never touches the network."""
    return ValidationContext(
        trust_roots=TRUST_ROOTS, allow_fetching=False, other_certs=[]
    )


def lta_spec():
    # ETSI-style: a CRL is usable when (validation_time - thisUpdate) does
    # not exceed the CRL's own validity period. Time-slide rewinds the
    # control time to within that window using the CRL's POE.
    revinfo_policy = CertRevTrustPolicy(
        revocation_checking_policy=REQUIRE_REVINFO,
        freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
    )
    sig_spec = SignatureValidationSpec(
        cert_validation_policy=CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build(TRUST_ROOTS),
            revinfo_policy=revinfo_policy,
        ),
        revinfo_gathering_policy=RevocationInfoGatheringSpec(
            online_fetching_rule=RevinfoOnlineFetchingRule.LOCAL_ONLY
        ),
    )
    return PdfSignatureValidationSpec(sig_spec)


def _testing_ca():
    from pyhanko_testing_commons.test_data.samples import TESTING_CA
    return TESTING_CA


def interm_crl(at):
    with freeze_time(at):
        return _testing_ca().service_registry.get_crl(
            ServiceLabel('interm'), at_time=at
        )


def root_crl(at):
    with freeze_time(at):
        return _testing_ca().service_registry.get_crl(
            ServiceLabel('root'), at_time=at
        )


def signer_ocsp(at):
    """Good (non-revoked) OCSP response for signer1, issued by interm-ocsp."""
    from asn1crypto import algos, ocsp
    from certomancer.registry import EntityLabel

    ca = _testing_ca()
    cert = FROM_CA.signing_cert
    cert_id = ocsp.CertId(
        {
            'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
            'issuer_name_hash': ca.entities.get_name_hash(
                EntityLabel('interm'), 'sha256'
            ),
            'issuer_key_hash': INTERM_CERT.public_key.sha256,
            'serial_number': cert.serial_number,
        }
    )
    with freeze_time(at):
        responder = ca.service_registry.summon_responder(
            ServiceLabel('interm'), at_time=at
        )
        return responder.assemble_simple_ocsp_responses(
            [responder.format_single_ocsp_response(cert_id, INTERM_CERT)]
        )


def tsa1_fixed(at=None):
    return timestamps.DummyTimeStamper(
        tsa_cert=TSA_CERT,
        tsa_key=_testing_ca().key_set.get_private_key('tsa'),
        certs_to_embed=FROM_CA.cert_registry,
        fixed_dt=at,
        override_md='sha256',
    )


def tsa2_fixed(at=None):
    return timestamps.DummyTimeStamper(
        tsa_cert=TSA2_CERT,
        tsa_key=_testing_ca().key_set.get_private_key('tsa2'),
        certs_to_embed=FROM_CA.cert_registry,
        fixed_dt=at,
        override_md='sha256',
    )


def minimal_pdf_bytes():
    return bytes(MINIMAL_ONE_FIELD)
