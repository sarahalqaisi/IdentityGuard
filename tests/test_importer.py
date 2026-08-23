import json

import pytest

from app.seed import demo_dataset
from app.services.importer import DatasetImportError, MAX_INPUT_BYTES, parse_dataset


def raw_demo():
    return demo_dataset().model_dump_json().encode()


def test_valid_dataset_and_deterministic_seed():
    assert parse_dataset(raw_demo()) == demo_dataset()
    assert demo_dataset().metadata["synthetic"] is True
    assert demo_dataset().metadata["seed"] == 20250823


@pytest.mark.parametrize("raw", [b"not-json", b"[]", b"{}"])
def test_malformed_inputs_fail_safely(raw):
    with pytest.raises(DatasetImportError):
        parse_dataset(raw)


def test_duplicate_ids_and_unknown_references_are_rejected():
    payload = demo_dataset().model_dump(mode="json")
    payload["users"].append(payload["users"][0])
    with pytest.raises(DatasetImportError, match="duplicate user"):
        parse_dataset(json.dumps(payload).encode())
    payload = demo_dataset().model_dump(mode="json")
    payload["user_groups"][0]["target_id"] = "unknown"
    with pytest.raises(DatasetImportError, match="unknown reference"):
        parse_dataset(json.dumps(payload).encode())


def test_size_limit():
    with pytest.raises(DatasetImportError, match="2 MB"):
        parse_dataset(b"x" * (MAX_INPUT_BYTES + 1))
