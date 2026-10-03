import pytest
from rlcheck.engine.safety import (
    SafetyConfig,
    validate_safety,
    MAX_ATTEMPTS_HARD_LIMIT,
    MIN_INTERVAL_HARD_LIMIT,
    MAX_TIMEOUT,
    DEFAULT_ATTEMPTS,
    DEFAULT_INTERVAL,
    DEFAULT_TIMEOUT,
)


def test_safety_config_defaults():
    cfg = SafetyConfig()
    assert cfg.max_attempts == DEFAULT_ATTEMPTS
    assert cfg.min_interval == DEFAULT_INTERVAL
    assert cfg.timeout == DEFAULT_TIMEOUT


def test_safety_config_clamping():
    # Attempting to exceed hard limits will be clamped by __post_init__
    cfg = SafetyConfig(max_attempts=100, min_interval=0.1, timeout=120)
    assert cfg.max_attempts == MAX_ATTEMPTS_HARD_LIMIT
    assert cfg.min_interval == MIN_INTERVAL_HARD_LIMIT
    assert cfg.timeout == MAX_TIMEOUT


def test_validate_safety_valid():
    cfg = SafetyConfig(max_attempts=20, min_interval=2.5, timeout=20)
    valid, msg = validate_safety(cfg)
    assert valid is True
    assert msg == ""


def test_validate_safety_invalid_attempts():
    cfg = SafetyConfig()
    cfg.max_attempts = 0
    valid, msg = validate_safety(cfg)
    assert valid is False
    assert "at least 1" in msg

    cfg.max_attempts = 51
    valid, msg = validate_safety(cfg)
    assert valid is False
    assert "exceed hard limit" in msg


def test_validate_safety_invalid_interval():
    cfg = SafetyConfig()
    cfg.min_interval = 0.5
    valid, msg = validate_safety(cfg)
    assert valid is False
    assert "Interval must be >=" in msg


def test_validate_safety_invalid_timeout():
    cfg = SafetyConfig()
    cfg.timeout = 0
    valid, msg = validate_safety(cfg)
    assert valid is False
    assert "Timeout must be at least 1" in msg

    cfg.timeout = 61
    valid, msg = validate_safety(cfg)
    assert valid is False
    assert "Timeout exceeds hard limit" in msg
