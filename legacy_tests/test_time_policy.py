from datetime import datetime, timedelta, timezone

import pytest

from core.time_policy import TimePolicy


def test_valid_request():
    policy = TimePolicy()

    now = datetime.now(timezone.utc)
    issued_at = now.isoformat()

    decision = policy.validate(
        issued_at=issued_at,
        ttl=30,
        now=now,
    )

    assert decision.valid is True
    assert decision.reason == "VALID"


def test_zero_ttl_is_invalid():
    policy = TimePolicy()

    now = datetime.now(timezone.utc)

    decision = policy.validate(
        issued_at=now.isoformat(),
        ttl=0,
        now=now,
    )

    assert decision.valid is False
    assert decision.reason == "INVALID_TTL"


def test_negative_ttl_is_invalid():
    policy = TimePolicy()

    now = datetime.now(timezone.utc)

    decision = policy.validate(
        issued_at=now.isoformat(),
        ttl=-10,
        now=now,
    )

    assert decision.valid is False
    assert decision.reason == "INVALID_TTL"


def test_ttl_above_maximum_is_invalid():
    policy = TimePolicy()

    now = datetime.now(timezone.utc)

    decision = policy.validate(
        issued_at=now.isoformat(),
        ttl=301,
        now=now,
    )

    assert decision.valid is False
    assert decision.reason == "INVALID_TTL"


def test_invalid_issued_at_is_rejected():
    policy = TimePolicy()

    decision = policy.validate(
        issued_at="esto-no-es-una-fecha",
        ttl=30,
    )

    assert decision.valid is False
    assert decision.reason == "INVALID_ISSUED_AT"


def test_missing_timezone_is_rejected():
    policy = TimePolicy()

    decision = policy.validate(
        issued_at="2026-09-23T10:00:00",
        ttl=30,
    )

    assert decision.valid is False
    assert decision.reason == "INVALID_ISSUED_AT"


def test_expired_request():
    policy = TimePolicy()

    issued_at = datetime(
        2026,
        9,
        23,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    now = issued_at + timedelta(seconds=31)

    decision = policy.validate(
        issued_at=issued_at.isoformat(),
        ttl=30,
        now=now,
    )

    assert decision.valid is False
    assert decision.reason == "EXPIRED"


def test_request_at_exact_expiration_is_expired():
    policy = TimePolicy()

    issued_at = datetime(
        2026,
        9,
        23,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    now = issued_at + timedelta(seconds=30)

    decision = policy.validate(
        issued_at=issued_at.isoformat(),
        ttl=30,
        now=now,
    )

    assert decision.valid is False
    assert decision.reason == "EXPIRED"


def test_request_before_expiration_is_valid():
    policy = TimePolicy()

    issued_at = datetime(
        2026,
        9,
        23,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    now = issued_at + timedelta(seconds=29)

    decision = policy.validate(
        issued_at=issued_at.isoformat(),
        ttl=30,
        now=now,
    )

    assert decision.valid is True
    assert decision.reason == "VALID"


def test_non_integer_ttl_is_rejected():
    policy = TimePolicy()

    now = datetime.now(timezone.utc)

    decision = policy.validate(
        issued_at=now.isoformat(),
        ttl="30",
        now=now,
    )

    assert decision.valid is False
    assert decision.reason == "INVALID_TTL"


def test_boolean_ttl_is_rejected():
    policy = TimePolicy()

    now = datetime.now(timezone.utc)

    decision = policy.validate(
        issued_at=now.isoformat(),
        ttl=True,
        now=now,
    )

    assert decision.valid is False
    assert decision.reason == "INVALID_TTL"


def test_custom_maximum_ttl():
    policy = TimePolicy(max_ttl_seconds=60)

    now = datetime.now(timezone.utc)

    decision = policy.validate(
        issued_at=now.isoformat(),
        ttl=61,
        now=now,
    )

    assert decision.valid is False
    assert decision.reason == "INVALID_TTL"


def test_z_suffix_is_accepted():
    policy = TimePolicy()

    now = datetime(
        2026,
        9,
        23,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    decision = policy.validate(
        issued_at="2026-09-23T10:00:00Z",
        ttl=30,
        now=now,
    )

    assert decision.valid is True
    assert decision.reason == "VALID"
