"""Shared text scrubbing for outbound log surfaces.

Single source of truth so the W&B handler series feed, the W&B console
capture (via stdout/stderr), and pm2's view of stdout all apply identical
drop/redact rules. Keeps decrypted miner endpoints — the whole reason
commitments exist — out of every observability surface.
"""

import re
import sys
import threading


# ─── Redaction patterns ──────────────────────────────────────────────

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")

# IPv6 — require the compressed `::` form, which every modern stringifier
# produces. Avoids false-positives on HH:MM:SS timestamps.
_IPV6_RE = re.compile(r"\[?[A-Fa-f0-9:]*::[A-Fa-f0-9:]+\]?(?::\d{1,5})?")

# Any URL: scheme://host... whitespace-terminated.
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>]+")

# Hostnames that are safe to leave un-redacted. These never carry miner
# endpoint information — they're infra/docs/UI links we actively want to
# remain clickable in logs (e.g. the wandb run URL printed at init).
_URL_HOST_ALLOWLIST = (
    "wandb.ai",
    "wandb.com",
    "wandb.io",
    "github.com",
    "anthropic.com",
    "opentensor.ai",
    "bittensor.com",
    "conversations.xyz",   # CGP backend; not a miner
)


def _redact_url(match: re.Match) -> str:
    url = match.group(0)
    # Cheap allowlist check — any allowed host substring inside the URL means
    # it's safe to keep verbatim.
    if any(host in url for host in _URL_HOST_ALLOWLIST):
        return url
    return "[REDACTED_URL]"

# Dotted hostname:port (e.g. miner.example.com:8080).
_HOSTPORT_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}:\d{1,5}\b"
)

# Bare host:port — covers `myhost:8080`. Dots are not allowed in the host
# portion (otherwise we'd misclassify source paths like `dendrite.py:262`);
# truly bare names go through _BAREHOSTPORT_RE, dotted names through
# _HOSTPORT_RE with the code-file-extension guard applied separately.
_BAREHOSTPORT_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9-]{1,253}:\d{2,5}\b")

# Source file extensions that look like a TLD to _HOSTPORT_RE but aren't.
# When the "TLD" of a host:port match is one of these, we leave the text
# alone so log entries like `bittensor:dendrite.py:262` stay readable.
_SOURCE_FILE_TLDS = frozenset({
    "py", "pyc", "pyx", "pyi",
    "js", "ts", "tsx", "jsx", "mjs",
    "go", "rs", "rb", "java", "kt", "scala", "swift",
    "c", "cc", "cpp", "cxx", "h", "hpp", "hxx",
    "cs", "vb", "fs",
    "sh", "bash", "zsh", "fish",
    "html", "htm", "xml", "css", "scss", "sass",
    "json", "yaml", "yml", "toml", "ini", "cfg", "conf",
    "md", "rst", "txt", "log",
    "sql", "graphql",
    "vue", "svelte",
})


def _redact_hostport(match: re.Match) -> str:
    """Redact a host:port unless the TLD is actually a source-file extension."""
    text = match.group(0)
    # text == "host.tld:port"; split off port, then TLD
    host_part = text.rsplit(":", 1)[0]
    tld = host_part.rsplit(".", 1)[-1].lower()
    if tld in _SOURCE_FILE_TLDS:
        return text
    return "[REDACTED_ENDPOINT]"


def _redact_barehost(match: re.Match) -> str:
    """Redact a bare host:port unless the host is a source-file extension.

    Handles substrings like `py:46` that appear when the host-extension
    regex left a `*.py:N` intact and the bare regex then matched the tail.
    """
    text = match.group(0)
    host_part = text.rsplit(":", 1)[0].lower()
    if host_part in _SOURCE_FILE_TLDS:
        return text
    return "[REDACTED_ENDPOINT]"


# ─── Drop list ────────────────────────────────────────────────────────
#
# Substrings that almost certainly mean a log line contains miner endpoint
# data we're trying to keep private. Drop entire matching lines rather than
# rely on regex redaction — defense in depth.

_DROP_SUBSTRINGS = (
    "ClientConnectorError",
    "ContentTypeError",
    "ServerDisconnectedError",
    "ServerTimeoutError",
    "ClientPayloadError",
    "ClientResponseError",
    "ConnectionRefusedError",
    "Cannot connect to host",
    "Connect call failed",
    "/CgSynapse",
    "axon=",
    "endpoint=",
    "Dendrite ",
    "dendrite=",
)


def should_drop(line: str) -> bool:
    return any(s in line for s in _DROP_SUBSTRINGS)


def scrub(message: str) -> str:
    """Redact endpoint-shaped tokens. Order matters: URLs first so a full
    `http://1.2.3.4:5/CgSynapse` becomes one redaction token, then narrower
    IP/host patterns mop up bare cases.
    """
    message = _URL_RE.sub(_redact_url, message)
    message = _IPV4_RE.sub("[REDACTED_ENDPOINT]", message)
    message = _IPV6_RE.sub("[REDACTED_ENDPOINT]", message)
    message = _HOSTPORT_RE.sub(_redact_hostport, message)
    message = _BAREHOSTPORT_RE.sub(_redact_barehost, message)
    return message


# ─── stdout / stderr scrubbing wrapper ───────────────────────────────


class _ScrubbingStream:
    """File-like wrapper that drops sensitive lines and redacts the rest
    before forwarding to the real stream.

    Reentrancy is guarded so a write() that itself triggers logging (rare,
    but possible if the underlying stream raises) doesn't loop.
    """

    def __init__(self, real_stream):
        self._real = real_stream
        self._reentrant = threading.local()

    def write(self, data):
        if not isinstance(data, str):
            # Some loggers pass bytes; pass through unmodified rather than
            # making assumptions about encoding.
            return self._real.write(data)
        if getattr(self._reentrant, "active", False):
            return self._real.write(data)
        if not data:
            return 0
        self._reentrant.active = True
        try:
            # splitlines(keepends=True) keeps separators so a write of
            # "a\nb" preserves boundaries exactly.
            lines = data.splitlines(keepends=True)
            out = []
            for line in lines:
                if should_drop(line):
                    continue
                out.append(scrub(line))
            return self._real.write("".join(out))
        finally:
            self._reentrant.active = False

    def flush(self):
        return self._real.flush()

    def __getattr__(self, name):
        # Proxy everything else (isatty, fileno, etc.) to the real stream.
        return getattr(self._real, name)


def install_stdio_scrubbers() -> None:
    """Replace sys.stdout and sys.stderr with scrubbing wrappers.

    Idempotent: subsequent calls are no-ops. Safe to call before or after
    wandb.init — the wrappers stay attached for the process lifetime.

    NOTE: This only catches writes that go through sys.stdout / sys.stderr
    at the Python level. Loguru (used by bittensor) caches the original
    stderr reference at import time and bypasses this wrapper. Use
    install_fd_scrubbers() if you need to filter loguru output too.
    """
    if not isinstance(sys.stdout, _ScrubbingStream):
        sys.stdout = _ScrubbingStream(sys.stdout)
    if not isinstance(sys.stderr, _ScrubbingStream):
        sys.stderr = _ScrubbingStream(sys.stderr)


# ─── file-descriptor level scrubbing (catches loguru) ────────────────


_fd_scrubbers_installed = False


def _fd_reader_loop(read_fd: int, real_fd: int) -> None:
    """Read from read_fd, scrub line-by-line, write to real_fd.

    Keeps a small line buffer so a write that doesn't end with a newline
    still gets scrubbed when its line completes.
    """
    import os
    buf = b""
    while True:
        try:
            chunk = os.read(read_fd, 4096)
        except OSError:
            break
        if not chunk:
            # Pipe closed (process shutting down). Flush any partial line.
            if buf:
                try:
                    text = buf.decode(errors="replace")
                    if not should_drop(text):
                        os.write(real_fd, scrub(text).encode())
                except OSError:
                    pass
            break

        buf += chunk
        # Split off complete lines; keep the last partial fragment in buf.
        while True:
            nl = buf.find(b"\n")
            if nl < 0:
                break
            line = buf[: nl + 1]
            buf = buf[nl + 1 :]
            try:
                text = line.decode(errors="replace")
            except Exception:
                # If we can't decode, pass through unchanged so we don't
                # silently lose log data.
                try:
                    os.write(real_fd, line)
                except OSError:
                    return
                continue
            if should_drop(text):
                continue
            try:
                os.write(real_fd, scrub(text).encode())
            except OSError:
                return


def install_fd_scrubbers() -> None:
    """Redirect fd 1 (stdout) and fd 2 (stderr) through a scrubbing pipe.

    Anything written to those file descriptors — including loguru output
    from bittensor, native libraries, child processes — passes through our
    scrub/drop rules before reaching the real underlying fds.

    Idempotent: subsequent calls are no-ops.

    Must be called *before* wandb.init() if you want wandb's console
    capture to see scrubbed text. wandb 0.18's console="auto" mode uses
    its own fd manipulation, so install order matters.
    """
    import os
    import threading

    global _fd_scrubbers_installed
    if _fd_scrubbers_installed:
        return

    for fd in (1, 2):
        real_fd = os.dup(fd)
        read_fd, write_fd = os.pipe()
        os.dup2(write_fd, fd)
        os.close(write_fd)

        t = threading.Thread(
            target=_fd_reader_loop,
            args=(read_fd, real_fd),
            daemon=True,
            name=f"_scrubber_fd{fd}",
        )
        t.start()

    _fd_scrubbers_installed = True
