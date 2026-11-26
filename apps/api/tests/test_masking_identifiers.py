"""Masking never rewrites record ids: a digit run inside a UUID or a hex digest is not a phone or card number."""

import uuid

from app.services.sensitive_data_detection_service import private_sensitive_spans


def test_random_uuids_are_never_masked() -> None:
    for _ in range(2000):
        text = '{"evidence_ref": "%s", "ids": ["%s"]}' % (uuid.uuid4(), uuid.uuid4())
        assert private_sensitive_spans(text) == []


def test_known_phone_shaped_uuid_and_digest_are_left_alone() -> None:
    for value in ("7e4aa439-be3e-4962-8867-2b4f1da6761f", "b3378931-22ae-4346-a3b8-2affe40b09f0", "4111111111111111" * 4):
        assert private_sensitive_spans(f"ref {value} done") == []


def test_real_phone_and_card_next_to_an_id_are_still_masked() -> None:
    text = "id 7e4aa439-be3e-4962-8867-2b4f1da6761f call +971 50 123 4567 card 4111 1111 1111 1111"
    kinds = {kind for _start, _end, kind in private_sensitive_spans(text)}
    assert "phone" in kinds and "credit_card" in kinds
