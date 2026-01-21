"""Tests for NmapScanner module."""
import pytest
import argparse
from unittest.mock import patch, MagicMock
import asyncio
import json
from NmapScanner import (
    validate_ip,
    validate_port_range,
    validate_target,
    cached_scan,
    async_scan,
    save_results,
    perform_scan,
)


# Mocking the nmap.PortScanner class
@pytest.fixture
def mock_nmap_scanner():
    with patch("NmapScanner.nmap.PortScanner") as mock_scanner:
        yield mock_scanner


# Mocking asyncio.to_thread for async scanning
@pytest.fixture
def mock_async_to_thread():
    with patch("asyncio.to_thread") as mock_to_thread:
        yield mock_to_thread


# Mocking file operations for save_results
@pytest.fixture
def mock_file_operations():
    with patch("builtins.open", create=True) as mock_open:
        yield mock_open


# --- validate_ip tests ---
class TestValidateIp:
    def test_valid_ip(self):
        assert validate_ip("192.168.1.1") == "192.168.1.1"
        assert validate_ip("10.0.0.1") == "10.0.0.1"

    def test_invalid_ip_out_of_range(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_ip("256.256.256.256")

    def test_invalid_ip_format(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_ip("invalid_ip")


# --- validate_port_range tests ---
class TestValidatePortRange:
    def test_valid_range(self):
        assert validate_port_range("20-80") == "20-80"
        assert validate_port_range("1-65535") == "1-65535"

    def test_valid_comma_separated(self):
        assert validate_port_range("80,443,8080") == "80,443,8080"

    def test_valid_mixed(self):
        assert validate_port_range("22,80-443,8080") == "22,80-443,8080"

    def test_invalid_port_zero(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_port_range("0-100")

    def test_invalid_range_reversed(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_port_range("100-50")


# --- validate_target tests ---
class TestValidateTarget:
    def test_valid_ip(self):
        assert validate_target("192.168.1.1") == "192.168.1.1"

    def test_valid_cidr(self):
        assert validate_target("192.168.1.0/24") == "192.168.1.0/24"

    def test_invalid_target(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_target("invalid_target")


# --- cached_scan tests ---
def test_cached_scan(mock_nmap_scanner):
    mock_instance = mock_nmap_scanner.return_value
    mock_instance.scan.return_value = {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}

    # Clear cache before test
    cached_scan.cache_clear()

    result = cached_scan("192.168.1.1", "80", "syn")
    assert result == {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}
    mock_instance.scan.assert_called_once_with(hosts="192.168.1.1", ports="80", arguments="-sS -T4 -v")


# --- async_scan tests ---
@pytest.mark.asyncio
async def test_async_scan(mock_async_to_thread, mock_nmap_scanner):
    mock_instance = mock_nmap_scanner.return_value
    mock_instance.scan.return_value = {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}
    mock_async_to_thread.return_value = {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}

    targets = ["192.168.1.1", "192.168.1.2"]
    results = await async_scan(targets, "80", "syn")
    assert len(results) == 2


# --- save_results tests ---
class TestSaveResults:
    def test_save_json(self, mock_file_operations, tmp_path):
        results = {"192.168.1.1": {"tcp": {80: {"state": "open", "name": "http"}}}}
        with patch("builtins.open", mock_file_operations):
            save_results(results, "output", "json")
        mock_file_operations.assert_called_once()


# --- perform_scan tests ---
def test_perform_scan(mock_nmap_scanner):
    mock_instance = mock_nmap_scanner.return_value
    mock_instance.scan.return_value = {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}

    # Clear cache before test
    cached_scan.cache_clear()

    results = perform_scan("192.168.1.1", "80", "syn")
    assert "192.168.1.1" in results