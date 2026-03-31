"""Validação dos fixes implementados — formatado como suite pytest."""
import ast
import inspect
import re
import warnings

warnings.filterwarnings("ignore")


# ─── BUG-07: websockets import seguro ────────────────────────────────────────

def test_bug07_websockets_safe_import():
    from spectra.modules.xss_scanner import XSSScanner, WEBSOCKETS_AVAILABLE  # noqa: F401
    assert isinstance(WEBSOCKETS_AVAILABLE, bool)


# ─── BUG-05: versão centralizada ─────────────────────────────────────────────

def test_bug05_version_exists():
    import spectra.core.config as cfg_mod
    assert hasattr(cfg_mod, "version"), "config.py não expõe 'version'"


def test_bug05_version_updated():
    import spectra.core.config as cfg_mod
    assert cfg_mod.version != "1.0.0", f"versão ainda é a antiga: {cfg_mod.version}"


# ─── BUG-02: LFI session lock ────────────────────────────────────────────────

def test_bug02_lfi_has_session_lock():
    from spectra.modules.lfi_scanner import LFIScanner
    src = inspect.getsource(LFIScanner)
    assert "_session_lock" in src and "threading.Lock()" in src


def test_bug02_lfi_uses_lock_context():
    from spectra.modules.lfi_scanner import LFIScanner
    src = inspect.getsource(LFIScanner)
    assert "with self._session_lock:" in src


# ─── BUG-03/04: SSRF timing e remoção de 127.0.0.1 ──────────────────────────

def test_bug03_ssrf_timing_before_request():
    from spectra.modules.ssrf_scanner import SSRFScanner
    src = inspect.getsource(SSRFScanner)
    idx_start = src.find("start_time = time.time()")
    assert idx_start != -1, "start_time não encontrado no SSRFScanner"
    idx_get = src.find(".get(", idx_start)
    assert idx_get != -1, "nenhum .get() encontrado após start_time"


def test_bug04_ssrf_127_removed_from_indicators():
    from spectra.modules.ssrf_scanner import SSRFScanner
    src = inspect.getsource(SSRFScanner)
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == "ssrf_indicators":
                    for el in ast.walk(node.value):
                        if isinstance(el, ast.Constant) and el.value == "127.0.0.1":
                            assert False, "127.0.0.1 ainda está em ssrf_indicators"


# ─── BUG-08: AdvancedDirectoryScanner workers=None sentinel ─────────────────

def test_bug08_directory_scanner_workers_default():
    from spectra.modules.directory_scanner import AdvancedDirectoryScanner
    sig = inspect.signature(AdvancedDirectoryScanner.__init__)
    w = sig.parameters.get("workers")
    assert w is not None, "parâmetro 'workers' não existe"
    assert w.default is None, f"default esperado None, got {w.default!r}"


def test_bug08_directory_scanner_autodetect():
    from spectra.modules.directory_scanner import AdvancedDirectoryScanner
    src = inspect.getsource(AdvancedDirectoryScanner)
    assert "workers is None" in src


# ─── BUG-09: create_session retorna _TimeoutSession ──────────────────────────

def test_bug09_create_session_returns_timeout_session():
    import requests
    from spectra.utils.network import _TimeoutSession, create_session
    sess = create_session()
    assert isinstance(sess, _TimeoutSession)
    assert issubclass(_TimeoutSession, requests.Session)


# ─── BUG-10: port scanner sem bare except ────────────────────────────────────

def test_bug10_no_bare_except_in_port_scanner():
    from spectra.modules.port_scanner import AdvancedPortScanner
    src = inspect.getsource(AdvancedPortScanner)
    bare = re.findall(r"^\s*except\s*:", src, re.MULTILINE)
    assert len(bare) == 0, f"bare except(s) encontrados: {len(bare)}"


# ─── BUG-11: normalize_risk consistente ──────────────────────────────────────

def test_bug11_normalize_risk_canonical():
    from spectra.core.report_generator import _normalize_risk as nr

    critico = nr("CRÍTICA")
    alto = nr("HIGH")
    medio = nr("medium")
    baixo = nr("baixo")

    cases = [
        ("CRÍTICA",   critico),
        ("Critical",  critico),
        ("CRITICAL",  critico),
        ("HIGH",      alto),
        ("Alto",      alto),
        ("high",      alto),
        ("medium",    medio),
        ("MEDIUM",    medio),
        ("Medio",     medio),
        ("baixo",     baixo),
        ("Low",       baixo),
    ]
    failures = []
    for raw, expected in cases:
        got = nr(raw)
        if got != expected:
            failures.append(f"_normalize_risk({raw!r}) -> {got!r} (esperado {expected!r})")
    assert not failures, "\n".join(failures)


# ─── BUG-14: XXE escape XML ──────────────────────────────────────────────────

def test_bug14_xxe_uses_saxutils():
    import spectra.modules.xxe_scanner as xxe_mod
    src = inspect.getsource(xxe_mod)
    assert "xml.sax.saxutils" in src


def test_bug14_xxe_attr_escape_applied():
    import spectra.modules.xxe_scanner as xxe_mod
    from spectra.modules.xxe_scanner import XXEScanner
    src_mod = inspect.getsource(xxe_mod)
    src_cls = inspect.getsource(XXEScanner)
    assert "xml_attr_escape" in src_cls or "xml_attr_escape" in src_mod


# ─── BUG-15: DNS old_timeout antes do try ────────────────────────────────────

def test_bug15_dns_old_timeout_defined():
    from spectra.modules.dns_analyzer import DNSAnalyzer
    src = inspect.getsource(DNSAnalyzer)
    assert "old_timeout = " in src, "old_timeout não encontrado no DNSAnalyzer"


# ─── ARQ-03: HTML report usa html.escape ─────────────────────────────────────

def test_arq03_html_escape_imported():
    from spectra.core.report_generator import ReportGenerator
    src = inspect.getsource(ReportGenerator)
    assert "import html" in src or "html.escape" in src


def test_arq03_html_escape_applied():
    from spectra.core.report_generator import ReportGenerator
    src = inspect.getsource(ReportGenerator)
    count = src.count("html.escape(")
    assert count >= 3, f"html.escape() encontrado apenas {count}x (esperado >=3)"
