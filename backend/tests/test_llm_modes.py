"""Air-gapped operation: in `local` mode only a self-hosted OpenAI-compatible
endpoint is ever contacted; in `off` mode no AI is called at all. The cloud
providers are replaced with tripwires to prove they are never reached."""
import pytest

from app import llm_client


class _Resp:
    def __init__(self, content):
        self._content = content

    def raise_for_status(self):
        pass

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


@pytest.fixture
def real_batch(monkeypatch):
    # conftest stubs classify_batch out for every test; these tests exercise it.
    import importlib
    monkeypatch.setattr(llm_client, "classify_batch", importlib.import_module("app.llm_client").__dict__["classify_batch"])
    tripwire = lambda *a, **k: (_ for _ in ()).throw(AssertionError("cloud provider called"))
    monkeypatch.setattr(llm_client, "_batch_groq", tripwire)
    monkeypatch.setattr(llm_client, "_batch_gemini", tripwire)
    monkeypatch.setattr(llm_client, "_try_groq", tripwire)
    monkeypatch.setattr(llm_client, "_try_gemini", tripwire)


def test_local_mode_uses_only_the_self_hosted_endpoint(monkeypatch, real_batch):
    calls = []

    def fake_post(url, **kw):
        calls.append((url, kw["json"]["model"]))
        return _Resp('{"r":[[0,"AC.telnet_enabled",true,0.9,"telnet on vty"]]}')

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setenv("AEGIS_LLM_MODE", "local")
    monkeypatch.setenv("AEGIS_LOCAL_LLM_URL", "http://10.0.0.9:11434/v1")
    monkeypatch.setenv("AEGIS_LOCAL_LLM_MODEL", "qwen2.5:7b-instruct")
    out = llm_client._classify_chunk(["transport input telnet", "ip cef"], [[], []])
    assert calls == [("http://10.0.0.9:11434/v1/chat/completions", "qwen2.5:7b-instruct")]
    assert out[0].canonical_field == "AC.telnet_enabled" and out[0].provider == "local"
    assert out[1].canonical_field == "UNKNOWN"  # omitted id in a complete response


def test_local_mode_output_is_validated_like_cloud_output(monkeypatch, real_batch):
    import httpx
    monkeypatch.setattr(httpx, "post", lambda url, **kw: _Resp('{"r":[[0,"AC.made_up_field",true,0.99,"x"]]}'))
    monkeypatch.setenv("AEGIS_LLM_MODE", "local")
    assert llm_client._classify_chunk(["transport input telnet"], [[]]) == [None]


def test_off_mode_calls_no_ai_at_all(monkeypatch, real_batch):
    import httpx
    monkeypatch.setattr(httpx, "post", lambda *a, **k: (_ for _ in ()).throw(AssertionError("AI called")))
    monkeypatch.setenv("AEGIS_LLM_MODE", "off")
    assert llm_client._classify_chunk(["transport input telnet"], [[]]) == [None]
    assert llm_client.classify("transport input telnet") is None


def test_mode_is_reported(client, monkeypatch):
    monkeypatch.setenv("AEGIS_LLM_MODE", "local")
    assert client.get("/stats").json()["llm_mode"] == "local"
