"""tests for vulcan.utils"""

from __future__ import annotations

import pytest

from vulcan.utils import check_port, safe_filename


class TestCheckPort:
    @pytest.mark.parametrize("value", [1, 80, 65535, "80", "1", "65535"])
    def test_valid_numeric(self, value):
        assert check_port(value) == int(value)

    @pytest.mark.parametrize("value", [0, -1, 65536, 1_000_000])
    def test_out_of_range_int(self, value):
        with pytest.raises(ValueError, match="1-65535"):
            check_port(value)

    def test_out_of_range_string(self):
        with pytest.raises(ValueError, match="1-65535"):
            check_port("70000")

    def test_any_returns_int_in_ephemeral_range(self):
        for _ in range(20):
            port = check_port("any")
            assert 1024 <= port <= 65535

    def test_known_variable(self):
        port = check_port("$http_ports")
        assert port in {80, 443, 8080, 8443}

    def test_unknown_variable_falls_back(self):
        port = check_port("$nonsense")
        assert 1024 <= port <= 65535

    @pytest.mark.parametrize("value", ["abc", "", "  ", None, 1.5, []])
    def test_invalid(self, value):
        with pytest.raises(ValueError):
            check_port(value)


class TestSafeFilename:
    def test_extension_and_prefix(self):
        name = safe_filename(prefix="test", suffix=".pcap")
        assert name.startswith("test-")
        assert name.endswith(".pcap")

    def test_uniqueness(self):
        names = {safe_filename() for _ in range(50)}
        assert len(names) == 50
