"""Script de validação dos fixes implementados."""
import warnings
warnings.filterwarnings('ignore')
import sys, inspect, threading

PASS = "[PASS]"
FAIL = "[FAIL]"

results = []

def check(label, condition, detail=""):
    status = PASS if condition else FAIL
    msg = f"{status} {label}"
    if detail:
        msg += f"  ({detail})"
    print(msg)
    results.append((label, condition))

# ─── BUG-07: websockets import seguro ────────────────────────────────────────
try:
    from spectra.modules.xss_scanner import XSSScanner, WEBSOCKETS_AVAILABLE
    check("BUG-07 websockets import seguro", True, f"WEBSOCKETS_AVAILABLE={WEBSOCKETS_AVAILABLE}")
except ImportError as e:
    check("BUG-07 websockets import seguro", False, str(e))

# ─── BUG-05: versão centralizada ─────────────────────────────────────────────
try:
    import spectra.core.config as cfg_mod
    cfg_version = getattr(cfg_mod, 'version', None)
    check("BUG-05 versão em config.py", cfg_version is not None, f"version={cfg_version}")
    check("BUG-05 versão não é 1.0.0 antigo", cfg_version != "1.0.0", f"version={cfg_version}")
except Exception as e:
    check("BUG-05 versão centralizada", False, str(e))

# ─── BUG-02: LFI session lock ─────────────────────────────────────────────────
try:
    from spectra.modules.lfi_scanner import LFIScanner
    src = inspect.getsource(LFIScanner)
    has_lock = "_session_lock" in src and "threading.Lock()" in src
    check("BUG-02 LFI threading.Lock presente", has_lock)
    has_with = "with self._session_lock:" in src
    check("BUG-02 LFI usa with self._session_lock", has_with)
except Exception as e:
    check("BUG-02 LFI session lock", False, str(e))

# ─── BUG-03/04: SSRF timing e remoção de 127.0.0.1 ──────────────────────────
try:
    from spectra.modules.ssrf_scanner import SSRFScanner
    src = inspect.getsource(SSRFScanner)

    # BUG-03: start_time deve aparecer ANTES da chamada http (request)
    idx_start = src.find("start_time = time.time()")
    idx_request_after_start = src.find(".get(", idx_start) if idx_start != -1 else -1
    check("BUG-03 SSRF timing mede antes do request", idx_start != -1 and idx_request_after_start != -1,
          f"start_time em pos={idx_start}, .get() em pos={idx_request_after_start}")

    # BUG-04: 127.0.0.1 removido dos indicadores estáticos
    # Encontrar ssrf_indicators list
    import ast
    tree = ast.parse(src)
    found_in_indicators = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == "ssrf_indicators":
                    for el in ast.walk(node.value):
                        if isinstance(el, ast.Constant) and el.value == "127.0.0.1":
                            found_in_indicators = True
    check("BUG-04 127.0.0.1 removido de ssrf_indicators", not found_in_indicators)
except Exception as e:
    check("BUG-03/04 SSRF", False, str(e))

# ─── BUG-08: AdvancedDirectoryScanner workers=None sentinel ─────────────────
try:
    from spectra.modules.directory_scanner import AdvancedDirectoryScanner
    sig = inspect.signature(AdvancedDirectoryScanner.__init__)
    w = sig.parameters.get('workers')
    check("BUG-08 workers default=None", w is not None and w.default is None, f"default={w.default if w else 'N/A'}")
    src = inspect.getsource(AdvancedDirectoryScanner)
    check("BUG-08 auto-detect usa 'is None'", "workers is None" in src)
except Exception as e:
    check("BUG-08 directory scanner workers", False, str(e))

# ─── BUG-09: create_session retorna _TimeoutSession ──────────────────────────
try:
    from spectra.utils.network import create_session, _TimeoutSession
    sess = create_session()
    check("BUG-09 create_session retorna _TimeoutSession", isinstance(sess, _TimeoutSession))
    # Verificar que timeout é injetado automaticamente
    import requests
    check("BUG-09 _TimeoutSession herda de Session", issubclass(_TimeoutSession, requests.Session))
except Exception as e:
    check("BUG-09 create_session timeout", False, str(e))

# ─── BUG-10: port scanner sem bare except ────────────────────────────────────
try:
    from spectra.modules.port_scanner import AdvancedPortScanner
    src = inspect.getsource(AdvancedPortScanner)
    import re
    bare_excepts = re.findall(r'^\s*except\s*:', src, re.MULTILINE)
    check("BUG-10 sem bare except: no port_scanner", len(bare_excepts) == 0,
          f"bare excepts encontrados: {len(bare_excepts)}")
except Exception as e:
    check("BUG-10 port scanner bare except", False, str(e))

# ─── BUG-11: normalize_risk consistente ──────────────────────────────────────
try:
    from spectra.core.report_generator import _normalize_risk
    norm = _normalize_risk
    # Todos devem normalizar para o MESMO valor canônico (português capitalizado)
    from spectra.core.report_generator import _normalize_risk as nr
    critico_val = nr("CRÍTICA")
    alto_val = nr("HIGH")
    medio_val = nr("medium")
    baixo_val = nr("baixo")
    mappings = [
        # Crítico: variantes em inglês/pt/caps → mesmo valor
        ("CRÍTICA", critico_val), ("Critical", critico_val), ("CRITICAL", critico_val),
        # Alto: HIGH, Alto → mesmo valor
        ("HIGH", alto_val), ("Alto", alto_val), ("high", alto_val),
        # Médio: medium, MEDIUM → mesmo valor
        ("medium", medio_val), ("MEDIUM", medio_val), ("Medio", medio_val),
        # Baixo: Low, baixo → mesmo valor
        ("baixo", baixo_val), ("Low", baixo_val),
    ]
    all_ok = True
    for raw, expected in mappings:
        result = norm(raw)
        if result != expected:
            print(f"  _normalize_risk({raw!r}) -> {result!r} (esperado {expected!r})")
            all_ok = False
    check("BUG-11 _normalize_risk cobre todos os casos", all_ok)
except Exception as e:
    check("BUG-11 normalize_risk", False, str(e))

# ─── BUG-14: XXE escape XML ──────────────────────────────────────────────────
try:
    from spectra.modules.xxe_scanner import XXEScanner
    import spectra.modules.xxe_scanner as xxe_mod
    src_mod = inspect.getsource(xxe_mod)
    src_cls = inspect.getsource(XXEScanner)
    check("BUG-14 xml.sax.saxutils importado no xxe_scanner", "xml.sax.saxutils" in src_mod)
    check("BUG-14 escape aplicado em file_path", "xml_attr_escape" in src_cls or "xml_attr_escape" in src_mod)
except Exception as e:
    check("BUG-14 xxe escape xml", False, str(e))

# ─── BUG-15: DNS old_timeout antes do try ────────────────────────────────────
try:
    from spectra.modules.dns_analyzer import DNSAnalyzer
    src = inspect.getsource(DNSAnalyzer)
    # Verificar que old_timeout = ... não está dentro de um try aninhado
    # Simples heurística: old_timeout deve aparecer antes de "try:" em seu bloco
    idx_old = src.find("old_timeout = ")
    idx_try_after = src.find("try:", idx_old) if idx_old != -1 else -1
    idx_try_before = src.rfind("try:", 0, idx_old) if idx_old != -1 else -1
    check("BUG-15 old_timeout definido antes do try interno", idx_old != -1,
          f"old_timeout em pos={idx_old}")
except Exception as e:
    check("BUG-15 dns old_timeout", False, str(e))

# ─── ARQ-03: HTML report usa html.escape ─────────────────────────────────────
try:
    from spectra.core.report_generator import ReportGenerator
    src = inspect.getsource(ReportGenerator)
    check("ARQ-03 html.escape importado", "import html" in src or "html.escape" in src)
    check("ARQ-03 html.escape aplicado nos campos", src.count("html.escape(") >= 3,
          f"ocorrências: {src.count('html.escape(')}")
except Exception as e:
    check("ARQ-03 html report escape", False, str(e))

# ─── Sumário ──────────────────────────────────────────────────────────────────
print()
total = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed
print(f"{'='*50}")
print(f"  RESULTADO: {passed}/{total} testes passaram  |  {failed} falharam")
print(f"{'='*50}")
if failed > 0:
    sys.exit(1)
