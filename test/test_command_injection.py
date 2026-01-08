import subprocess
import pytest

from cra_demo_app.cli import ping_host

def test_ping_host_uses_safe_subprocess_invocation(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=args, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    ping_host("8.8.8.8")

    assert len(calls) == 1
    args, kwargs = calls[0]

    assert isinstance(args, list)
    assert args[:3] == ["ping", "-c", "1"]
    assert args[3] == "8.8.8.8"
    assert kwargs.get("shell", False) is False


@pytest.mark.parametrize(
    "payload",
    [
        "8.8.8.8; touch /tmp/pwned",
        "8.8.8.8 && touch /tmp/pwned",
        "8.8.8.8 | touch /tmp/pwned",
        "$(touch /tmp/pwned)",
        "`touch /tmp/pwned`",
        "-c 999 8.8.8.8",
        "--help",
        "8.8.8.8\n8.8.4.4",
    ],
)
def test_ping_host_rejects_injection_payloads(monkeypatch, payload):
    def fail_run(*_args, **_kwargs):
        raise AssertionError("subprocess.run should not be called for invalid host input")

    monkeypatch.setattr(subprocess, "run", fail_run)

    ping_host(payload)