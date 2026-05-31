"""Tests for bifrost.banner."""

from bifrost.banner import banner_text, print_startup_banner


def test_banner_text_contains_branding():
    text = banner_text("0.3.0")
    assert "BIFROST" in text or "██████╗" in text
    assert "R A I N B O W" in text
    assert "v0.3.0" in text
    assert "The Bridge Is Watched" in text


def test_banner_skips_when_not_tty(monkeypatch, capsys):
    monkeypatch.setenv("BIFROST_NO_BANNER", "")
    monkeypatch.delenv("BIFROST_NO_BANNER", raising=False)
    monkeypatch.setattr("bifrost.banner._stdout_is_tty", lambda: False)
    print_startup_banner()
    assert capsys.readouterr().out == ""
