from __future__ import annotations

import pytest

from roomkey.band.live import MissingBandCredentials, load_live_band_client_from_env


def test_live_band_requires_explicit_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("BAND_CREDENTIAL_FILE", str(tmp_path / "missing-band-credentials"))
    monkeypatch.delenv("BAND_REST_URL", raising=False)
    monkeypatch.delenv("BAND_API_KEY", raising=False)
    monkeypatch.delenv("BAND_AGENT_API_KEY", raising=False)

    with pytest.raises(MissingBandCredentials):
        load_live_band_client_from_env()
