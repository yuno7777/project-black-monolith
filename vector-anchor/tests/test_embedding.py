import pytest

from src.embedding import cosine


def test_cosine_rejects_mismatched_or_nonfinite_vectors():
    with pytest.raises(ValueError, match="equal dimensions"):
        cosine([1.0], [1.0, 0.0])
    with pytest.raises(ValueError, match="finite"):
        cosine([float("nan")], [1.0])
