import pytest

from keyhaven.crypto import KdfParams


@pytest.fixture
def fast_kdf():
    """Cheap scrypt settings so tests run quickly. Real vaults use the defaults (128 MiB)."""
    return lambda: KdfParams.new(n=2 ** 10, r=8, p=1)
