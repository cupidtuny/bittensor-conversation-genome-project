import logging
import threading

from conversationgenome.analytics._scrubber import scrub, should_drop


class WandbCountingHandler(logging.Handler):
    def __init__(self, wandb_lib_instance):
        super().__init__()
        self.wandb_lib = wandb_lib_instance
        # Reentrancy guard: if wandb_lib.log() raises and that raise gets
        # logged through bittensor, the handler would recurse and blow the
        # stack (we saw this during shutdown). Per-thread flag stops it.
        self._in_emit = threading.local()

    def emit(self, record):
        if getattr(self._in_emit, "active", False):
            return
        self._in_emit.active = True
        try:
            log_entry = self.format(record)

            # Drop sensitive bittensor dendrite/axon log lines outright.
            if should_drop(log_entry):
                return

            # Belt-and-suspenders: redact remaining IP / URL / host:port
            # patterns before forwarding to W&B.
            log_entry = scrub(log_entry)

            self.wandb_lib.log({"bt_log": log_entry})
        except Exception as e:
            # NB: use print, not bt.logging — otherwise this re-enters emit().
            print(f"Logging handler error: {e}")
        finally:
            self._in_emit.active = False
