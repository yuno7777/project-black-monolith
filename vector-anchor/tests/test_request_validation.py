"""Public retrieval and administrative corpus inputs are explicitly bounded."""

import pytest
from pydantic import ValidationError

from src.main import (
    MAX_DOCUMENT_BATCH_BYTES,
    MAX_DOCUMENT_TEXT_BYTES,
    MAX_QUERY_LENGTH,
    AddDocumentsRequest,
    Document,
    RetrieveRequest,
)


@pytest.mark.parametrize(
    "payload",
    [
        {"query": ""},
        {"query": "   "},
        {"query": "x", "k": 0},
        {"query": "x", "k": 101},
        {"query": "x" * (MAX_QUERY_LENGTH + 1)},
        {"query": "x", "unexpected": True},
    ],
)
def test_retrieval_inputs_are_bounded(payload):
    with pytest.raises(ValidationError):
        RetrieveRequest.model_validate(payload)


def test_queries_are_trimmed_and_valid_k_is_preserved():
    request = RetrieveRequest.model_validate({"query": "  incident response  ", "k": 5})
    assert request.query == "incident response"
    assert request.k == 5


def test_document_ids_and_text_are_bounded():
    with pytest.raises(ValidationError):
        Document.model_validate({"id": " ", "text": "content"})
    with pytest.raises(ValidationError):
        Document.model_validate({"id": "x" * 129, "text": "content"})
    with pytest.raises(ValidationError):
        Document.model_validate(
            {"id": "large", "text": "x" * (MAX_DOCUMENT_TEXT_BYTES + 1)}
        )


def test_document_batches_are_nonempty_unique_and_size_limited():
    with pytest.raises(ValidationError):
        AddDocumentsRequest.model_validate({"documents": []})
    with pytest.raises(ValidationError, match="unique"):
        AddDocumentsRequest.model_validate(
            {
                "documents": [
                    {"id": "same", "text": "first"},
                    {"id": "same", "text": "second"},
                ]
            }
        )

    text = "x" * (MAX_DOCUMENT_TEXT_BYTES - 1)
    count = (MAX_DOCUMENT_BATCH_BYTES // len(text)) + 1
    with pytest.raises(ValidationError, match="document batch"):
        AddDocumentsRequest.model_validate(
            {
                "documents": [
                    {"id": f"doc-{index}", "text": text}
                    for index in range(count)
                ]
            }
        )
