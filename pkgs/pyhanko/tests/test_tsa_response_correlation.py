"""Offline RFC 3161 response-correlation regressions."""

import asyncio
import hashlib
import threading
from datetime import UTC, datetime
from typing import Callable

import pytest
import requests
from asn1crypto import algos, cms, tsp
from certomancer.registry import KeyLabel
from pyhanko.sign.attributes import TSTProvider
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko.sign.timestamps import api as timestamp_api
from pyhanko.sign.timestamps.common_utils import (
    TimestampRequestError,
    dummy_digest,
)
from pyhanko.sign.timestamps.requests_client import RequestsHTTPTimeStamper
from pyhanko_testing_commons.test_data.samples import TESTING_CA
from pyhanko_testing_commons.test_utils.signing_commons import (
    FROM_CA,
    TSA_CERT,
)

TSA_URL = 'http://timestamp.invalid/tsa'
MD_ALGORITHM = 'sha256'
DIGEST_A = hashlib.sha256(b'first archival document').digest()
DIGEST_B = hashlib.sha256(b'second archival document').digest()
NONCE_A = 100_001
NONCE_B = 100_002
FIXED_TSA_TIME = datetime(2026, 1, 1, tzinfo=UTC)
TIMESTAMP_CONTENT_TYPE = 'application/timestamp-reply'


class FakeHttpResponse:
    def __init__(self, response: tsp.TimeStampResp):
        self.content = response.dump()
        self.headers = {'Content-Type': TIMESTAMP_CONTENT_TYPE}


class InMemoryTSATransport:
    def __init__(
        self,
        tsa: DummyTimeStamper,
        response_for: (
            Callable[[tsp.TimeStampReq], tsp.TimeStampResp] | None
        ) = None,
        swap_responses: bool = False,
    ):
        self.tsa = tsa
        self.response_for = response_for
        self.swap_responses = swap_responses
        self.requests: list[tsp.TimeStampReq] = []
        self._lock = threading.Lock()
        self._natural_responses: list[tsp.TimeStampResp | None] = []
        self._swap_barrier = threading.Barrier(2)

    def _natural_response(
        self, request: tsp.TimeStampReq
    ) -> tsp.TimeStampResp:
        if self.response_for is not None:
            return self.response_for(request)
        return self.tsa.request_tsa_response(request)

    def respond(self, raw_request: bytes) -> FakeHttpResponse:
        request = tsp.TimeStampReq.load(raw_request)
        if self.swap_responses:
            with self._lock:
                index = len(self.requests)
                self.requests.append(request)
                self._natural_responses.append(None)
            response = self._natural_response(request)
            with self._lock:
                self._natural_responses[index] = response
            self._swap_barrier.wait(timeout=5)
            swapped_response = self._natural_responses[1 - index]
            return FakeHttpResponse(swapped_response)

        with self._lock:
            self.requests.append(request)
        return FakeHttpResponse(self._natural_response(request))

    def post(
        self,
        url: str,
        data: bytes,
        headers: dict[str, str],
        auth,
        timeout: int,
    ) -> FakeHttpResponse:
        assert url == TSA_URL
        assert headers['Content-Type'] == 'application/timestamp-query'
        assert headers['Accept'] == TIMESTAMP_CONTENT_TYPE
        return self.respond(data)


class ReplayFirstResponseTransport:
    def __init__(self, tsa: DummyTimeStamper):
        self.tsa = tsa
        self.requests: list[tsp.TimeStampReq] = []
        self.first_response: tsp.TimeStampResp | None = None

    def respond(self, raw_request: bytes) -> FakeHttpResponse:
        request = tsp.TimeStampReq.load(raw_request)
        self.requests.append(request)
        response = self.tsa.request_tsa_response(request)
        if self.first_response is None:
            self.first_response = response
        return FakeHttpResponse(self.first_response)

    def post(
        self,
        url: str,
        data: bytes,
        headers: dict[str, str],
        auth,
        timeout: int,
    ) -> FakeHttpResponse:
        return self.respond(data)


def fixed_tsa(include_nonce: bool = True) -> DummyTimeStamper:
    return DummyTimeStamper(
        tsa_cert=TSA_CERT,
        tsa_key=TESTING_CA.key_set.get_private_key(KeyLabel('tsa')),
        certs_to_embed=FROM_CA.cert_registry,
        fixed_dt=FIXED_TSA_TIME,
        include_nonce=include_nonce,
    )


def install_client(
    monkeypatch,
    transport: InMemoryTSATransport | ReplayFirstResponseTransport,
    nonces: list[int],
    include_nonce: bool = True,
    *,
    patch_post: bool = True,
) -> RequestsHTTPTimeStamper:
    nonce_values = iter(nonces)
    monkeypatch.setattr(
        timestamp_api, 'get_nonce', lambda: next(nonce_values)
    )
    if patch_post:
        monkeypatch.setattr(requests, 'post', transport.post)
    client = RequestsHTTPTimeStamper(TSA_URL)
    client.include_nonce = include_nonce
    return client


def response_for_request(
    tsa: DummyTimeStamper,
    request: tsp.TimeStampReq,
    *,
    nonce: int | None = None,
    digest: bytes | None = None,
    algorithm: str | None = None,
) -> tsp.TimeStampResp:
    altered_request = tsp.TimeStampReq.load(request.dump())
    if nonce is not None:
        altered_request['nonce'] = cms.Integer(nonce)
    message_imprint = altered_request['message_imprint']
    if algorithm is not None:
        message_imprint['hash_algorithm'] = algos.DigestAlgorithm(
            {'algorithm': algorithm}
        )
    if digest is not None:
        message_imprint['hashed_message'] = digest
    return tsa.request_tsa_response(altered_request)


def refused_response(
    tsa: DummyTimeStamper, request: tsp.TimeStampReq
) -> tsp.TimeStampResp:
    response = tsa.request_tsa_response(request)
    response['status'] = tsp.PKIStatusInfo(
        {
            'status': 'rejection',
            'status_string': ['unrecognized policy'],
        }
    )
    return response


def tst_info(token: cms.ContentInfo) -> tsp.TSTInfo:
    return token['content']['encap_content_info']['content'].parsed


@pytest.mark.asyncio
async def test_concurrent_swap_returns_bad_nonce_to_each_caller(monkeypatch):
    transport = InMemoryTSATransport(fixed_tsa(), swap_responses=True)
    first_client = install_client(
        monkeypatch, transport, [NONCE_A, NONCE_B], include_nonce=True
    )
    second_client = install_client(
        monkeypatch,
        transport,
        [NONCE_A, NONCE_B],
        include_nonce=True,
        patch_post=False,
    )

    results = await asyncio.gather(
        first_client.async_timestamp(DIGEST_A, MD_ALGORITHM),
        second_client.async_timestamp(DIGEST_B, MD_ALGORITHM),
        return_exceptions=True,
    )

    assert all(isinstance(result, TimestampRequestError) for result in results)
    assert all('bad nonce' in str(result) for result in results)
    assert [
        request['message_imprint']['hashed_message'].native
        for request in transport.requests
    ] == [DIGEST_A, DIGEST_B]


@pytest.mark.asyncio
async def test_no_nonce_concurrent_swap_returns_wrong_imprint(monkeypatch):
    transport = InMemoryTSATransport(
        fixed_tsa(include_nonce=False), swap_responses=True
    )
    first_client = install_client(
        monkeypatch, transport, [], include_nonce=False
    )
    second_client = install_client(
        monkeypatch,
        transport,
        [],
        include_nonce=False,
        patch_post=False,
    )

    results = await asyncio.gather(
        first_client.async_timestamp(DIGEST_A, MD_ALGORITHM),
        second_client.async_timestamp(DIGEST_B, MD_ALGORITHM),
        return_exceptions=True,
    )

    assert all(isinstance(result, TimestampRequestError) for result in results)
    assert all('different message' in str(result) for result in results)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'mutation,expected_message',
    [
        ('nonce', 'bad nonce'),
        ('imprint', 'different message'),
        ('algorithm', 'digest algorithm'),
    ],
)
async def test_nonced_client_rejects_structurally_valid_mutation(
    monkeypatch, mutation, expected_message
):
    tsa = fixed_tsa()

    def mutate(request: tsp.TimeStampReq) -> tsp.TimeStampResp:
        if mutation == 'nonce':
            return response_for_request(tsa, request, nonce=NONCE_B)
        if mutation == 'imprint':
            return response_for_request(tsa, request, digest=DIGEST_B)
        return response_for_request(tsa, request, algorithm='sha384')

    transport = InMemoryTSATransport(tsa, response_for=mutate)
    client = install_client(monkeypatch, transport, [NONCE_A])

    with pytest.raises(TimestampRequestError, match=expected_message):
        await client.async_timestamp(DIGEST_A, MD_ALGORITHM)


@pytest.mark.asyncio
async def test_no_nonce_still_rejects_refused_status(monkeypatch):
    tsa = fixed_tsa(include_nonce=False)
    transport = InMemoryTSATransport(
        tsa, response_for=lambda request: refused_response(tsa, request)
    )
    client = install_client(
        monkeypatch, transport, [], include_nonce=False
    )

    with pytest.raises(TimestampRequestError, match='refused'):
        await client.async_timestamp(DIGEST_A, MD_ALGORITHM)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'mutation,expected_message',
    [
        ('imprint', 'different message'),
        ('algorithm', 'digest algorithm'),
    ],
)
async def test_no_nonce_still_checks_message_imprint(
    monkeypatch, mutation, expected_message
):
    tsa = fixed_tsa(include_nonce=False)

    def mutate(request: tsp.TimeStampReq) -> tsp.TimeStampResp:
        if mutation == 'imprint':
            return response_for_request(tsa, request, digest=DIGEST_B)
        return response_for_request(tsa, request, algorithm='sha384')

    transport = InMemoryTSATransport(tsa, response_for=mutate)
    client = install_client(
        monkeypatch, transport, [], include_nonce=False
    )

    with pytest.raises(TimestampRequestError, match=expected_message):
        await client.async_timestamp(DIGEST_A, MD_ALGORITHM)


@pytest.mark.asyncio
async def test_no_nonce_accepts_only_matching_response(monkeypatch):
    transport = InMemoryTSATransport(fixed_tsa(include_nonce=False))
    client = install_client(
        monkeypatch, transport, [], include_nonce=False
    )

    token = await client.async_timestamp(DIGEST_A, MD_ALGORITHM)
    info = tst_info(token)

    assert info['nonce'].native is None
    assert info['message_imprint']['hashed_message'].native == DIGEST_A
    assert (
        info['message_imprint']['hash_algorithm']['algorithm'].native
        == MD_ALGORITHM
    )


@pytest.mark.asyncio
async def test_dummy_response_cannot_be_treated_as_formal_result(
    monkeypatch,
):
    transport = ReplayFirstResponseTransport(fixed_tsa(include_nonce=False))
    client = install_client(
        monkeypatch, transport, [], include_nonce=False
    )
    provider = TSTProvider(
        digest_algorithm=MD_ALGORITHM,
        data_to_ts=DIGEST_A,
        timestamper=client,
        prehashed=True,
    )

    estimated_token = await provider.build_attr_value(dry_run=True)
    assert tst_info(estimated_token)['message_imprint'][
        'hashed_message'
    ].native == dummy_digest(MD_ALGORITHM)
    assert len(transport.requests) == 1

    with pytest.raises(TimestampRequestError, match='different message'):
        await provider.build_attr_value(dry_run=False)


@pytest.mark.asyncio
async def test_dummy_cache_is_reused_but_real_request_is_still_sent(
    monkeypatch,
):
    transport = InMemoryTSATransport(fixed_tsa())
    client = install_client(monkeypatch, transport, [NONCE_A, NONCE_B])

    first_estimate = await client.async_dummy_response(MD_ALGORITHM)
    second_estimate = await client.async_dummy_response(MD_ALGORITHM)
    assert second_estimate is first_estimate
    assert len(transport.requests) == 1

    formal_token = await client.async_timestamp(DIGEST_A, MD_ALGORITHM)
    assert len(transport.requests) == 2
    assert formal_token is not first_estimate
    assert tst_info(formal_token)['message_imprint'][
        'hashed_message'
    ].native == DIGEST_A
    assert tst_info(first_estimate)['message_imprint'][
        'hashed_message'
    ].native == dummy_digest(MD_ALGORITHM)
