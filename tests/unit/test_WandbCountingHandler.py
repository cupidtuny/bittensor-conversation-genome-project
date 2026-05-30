"""Regression tests for WandbCountingHandler endpoint scrubbing.

The encrypted commitment system exists to hide miner endpoints. Any leak via
W&B defeats that. These tests pin both the drop-list and redaction behavior.
"""

import logging
from unittest.mock import MagicMock

from conversationgenome.analytics._scrubber import scrub
from conversationgenome.analytics.WandbCountingHandler import WandbCountingHandler


def _make_handler():
    wandb_lib = MagicMock()
    handler = WandbCountingHandler(wandb_lib)
    handler.setFormatter(logging.Formatter("%(message)s"))
    return handler, wandb_lib


def _make_record(msg: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="bittensor",
        level=logging.DEBUG,
        pathname="validator.py",
        lineno=0,
        msg=msg,
        args=None,
        exc_info=None,
    )


# ─── drop-list ────────────────────────────────────────────────────────

class TestDropList:
    def test_drops_client_connector_error(self):
        handler, wandb_lib = _make_handler()
        handler.emit(_make_record(
            "ClientConnectorError#abc: Cannot connect to host 18.119.135.29:8210"
        ))
        wandb_lib.log.assert_not_called()

    def test_drops_content_type_error(self):
        handler, wandb_lib = _make_handler()
        handler.emit(_make_record(
            "ContentTypeError#xyz: 502, url='http://18.191.117.8:34030/CgSynapse'"
        ))
        wandb_lib.log.assert_not_called()

    def test_drops_any_cgsynapse_url_mention(self):
        handler, wandb_lib = _make_handler()
        handler.emit(_make_record("Posted to http://10.0.0.1:9000/CgSynapse"))
        wandb_lib.log.assert_not_called()

    def test_drops_server_disconnected(self):
        handler, wandb_lib = _make_handler()
        handler.emit(_make_record(
            "ServerDisconnectedError after 12s talking to miner"
        ))
        wandb_lib.log.assert_not_called()

    def test_drops_axon_blob(self):
        handler, wandb_lib = _make_handler()
        handler.emit(_make_record(
            "Calling axon=18.117.160.99:33111 with synapse foo"
        ))
        wandb_lib.log.assert_not_called()


# ─── scrub redaction ─────────────────────────────────────────────────

class TestScrub:
    def test_ipv4(self):
        assert "1.2.3.4" not in scrub("got 1.2.3.4:5000")
        assert "1.2.3.4" not in scrub("from 1.2.3.4 to here")
        assert "REDACTED" in scrub("got 1.2.3.4 today")

    def test_ipv6(self):
        out = scrub("got 2001:db8::1 talking to fe80::1:8080")
        assert "2001:db8" not in out
        assert "fe80" not in out
        assert "REDACTED" in out

    def test_url(self):
        out = scrub("calling http://miner.example.com:8080/synapse stuff")
        assert "miner.example.com" not in out
        assert "8080" not in out
        assert "REDACTED" in out

    def test_hostport(self):
        out = scrub("dialed miner1.example.com:9999 ok")
        assert "miner1.example.com" not in out
        assert "9999" not in out

    def test_bare_hostport(self):
        out = scrub("dialed myhost:8080 ok")
        assert "myhost:8080" not in out

    def test_does_not_redact_hh_mm_ss(self):
        """Timestamps must not be mistaken for IPv6 / host:port."""
        out = scrub("at 12:34:56 something happened")
        assert "12:34:56" in out

    def test_passes_innocuous_text(self):
        out = scrub("Validator step 1234 complete")
        assert out == "Validator step 1234 complete"


# ─── pass-through ────────────────────────────────────────────────────

class TestPassThrough:
    def test_clean_message_unchanged(self):
        handler, wandb_lib = _make_handler()
        handler.emit(_make_record("Validator step 1234 complete"))
        wandb_lib.log.assert_called_once_with({"bt_log": "Validator step 1234 complete"})

    def test_normal_validator_message_passes(self):
        """Routine validator messages must reach W&B — the previous source-
        module filter incorrectly dropped these."""
        handler, wandb_lib = _make_handler()
        handler.emit(_make_record("Commitment found for UID 126"))
        handler.emit(_make_record("Burning 0.9 to UID 81"))
        handler.emit(_make_record("resync_metagraph()"))
        handler.emit(_make_record("Looping for piece 1 out of 30"))
        assert wandb_lib.log.call_count == 4

    def test_redacts_ip_in_safe_message(self):
        handler, wandb_lib = _make_handler()
        handler.emit(_make_record("Heartbeat from 10.0.0.5"))
        wandb_lib.log.assert_called_once()
        sent = wandb_lib.log.call_args[0][0]["bt_log"]
        assert "10.0.0.5" not in sent
        assert "REDACTED" in sent


# ─── reentrancy ──────────────────────────────────────────────────────

class TestReentrancy:
    def test_no_recursion_when_wandb_raises(self):
        handler, wandb_lib = _make_handler()
        wandb_lib.log.side_effect = RuntimeError("upstream pipe dead")
        handler.emit(_make_record("step 5"))
        assert wandb_lib.log.call_count == 1
