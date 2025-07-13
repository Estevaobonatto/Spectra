# 🚀 Subdomain Scanner - Roadmap de Melhorias Avançadas

## 📋 Baseado na Análise das Melhores Ferramentas (2024)

### 🎯 **FASE 1: Core Improvements (CRÍTICO)**

#### **1. Multiple Discovery Techniques**
```python
class AdvancedSubdomainScanner:
    def __init__(self):
        self.discovery_methods = [
            'passive_apis',      # Like Subfinder
            'certificate_logs',  # Like Amass CT scanning
            'dns_brute_force',   # Traditional wordlist
            'permutation_engine', # Generate variations
            'zone_transfer',     # AXFR attempts
            'reverse_dns',       # IP range scanning
            'web_scraping'       # Search engines
        ]
```

#### **2. Passive API Integration (45+ Sources)**
```python
PASSIVE_SOURCES = {
    'certificate_transparency': [
        'crt.sh', 'censys.io', 'certspotter'
    ],
    'search_engines': [
        'google', 'bing', 'yahoo', 'duckduckgo'
    ],
    'threat_intelligence': [
        'virustotal', 'shodan', 'securitytrails'
    ],
    'dns_databases': [
        'dnsdumpster', 'netlas', 'binaryedge'
    ],
    'code_repositories': [
        'github', 'gitlab', 'bitbucket'
    ],
    'archives': [
        'wayback_machine', 'commoncrawl'
    ]
}
```

#### **3. Async Performance Engine**
```python
import asyncio
import aiohttp
import aiodns

class AsyncSubdomainResolver:
    def __init__(self, max_concurrent=1000):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.resolver = aiodns.DNSResolver()
        
    async def resolve_batch(self, subdomains):
        tasks = [self.resolve_subdomain(sub) for sub in subdomains]
        return await asyncio.gather(*tasks, return_exceptions=True)
```

#### **4. Rate Limiting & Anti-Detection**
```python
class RateLimiter:
    def __init__(self):
        self.delays = {
            'dns_queries': 0.1,      # DNS provider friendly
            'api_requests': 1.0,     # API rate limits
            'web_scraping': 2.0,     # Anti-bot measures
            'certificate_logs': 0.5   # CT log limits
        }
        
    async def adaptive_delay(self, source_type, error_rate):
        # Increase delay if error rate > 30%
        if error_rate > 0.3:
            self.delays[source_type] *= 1.5
```

### 🎯 **FASE 2: Advanced Discovery (IMPORTANTE)**

#### **5. Certificate Transparency Integration**
```python
class CertificateTransparency:
    async def query_crt_sh(self, domain):
        """Query crt.sh for certificates"""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        # Parse certificates and extract SANs
        
    async def query_censys(self, domain):
        """Query Censys certificates API"""
        # Requires API key
        
    def extract_subdomains_from_cert(self, cert_data):
        """Extract subdomains from certificate data"""
        subdomains = set()
        # Parse Subject Alternative Names (SANs)
        # Parse Common Names (CNs)
        return subdomains
```

#### **6. Subdomain Permutation Engine**
```python
class PermutationEngine:
    def __init__(self):
        self.prefixes = [
            'www', 'api', 'dev', 'test', 'stage', 'staging',
            'prod', 'admin', 'mail', 'email', 'ftp', 'ssh',
            'vpn', 'portal', 'app', 'mobile', 'web', 'cdn',
            'static', 'assets', 'media', 'img', 'images'
        ]
        self.suffixes = [
            'dev', 'test', 'staging', 'prod', 'old', 'new',
            'backup', 'temp', 'internal', 'external'
        ]
        
    def generate_permutations(self, base_subdomains):
        """Generate intelligent permutations"""
        permutations = set()
        for subdomain in base_subdomains:
            # Add prefixes: dev-api.domain.com
            # Add suffixes: api-dev.domain.com
            # Number variations: api1, api2, api01
            # Separator variations: api_dev, api.dev
        return permutations
```

#### **7. Real Subdomain Takeover Verification**
```python
class TakeoverVerifier:
    async def verify_takeover(self, subdomain, cname):
        """Actually verify if takeover is possible"""
        try:
            # HTTP request to check response
            response = await self.session.get(f"http://{subdomain}")
            
            # Check for takeover signatures
            takeover_signatures = {
                'github.io': 'There isn\'t a GitHub Pages site here',
                'herokuapp.com': 'No such app',
                'netlify.app': 'Not Found',
                'azurewebsites.net': 'Web Site not found'
            }
            
            for service, signature in takeover_signatures.items():
                if service in cname and signature in response.text:
                    return True, service
                    
        except Exception:
            pass
        return False, None
```

### 🎯 **FASE 3: Intelligence & Analytics (AVANÇADO)**

#### **8. Threat Intelligence Integration**
```python
class ThreatIntelligence:
    def __init__(self):
        self.apis = {
            'virustotal': VirusTotalAPI(),
            'shodan': ShodanAPI(),
            'securitytrails': SecurityTrailsAPI(),
            'urlvoid': URLVoidAPI()
        }
        
    async def enrich_subdomain(self, subdomain):
        """Enrich subdomain with threat intel"""
        intel = {}
        intel['malware_detected'] = await self.check_malware(subdomain)
        intel['suspicious_activity'] = await self.check_activity(subdomain)
        intel['historical_data'] = await self.get_history(subdomain)
        return intel
```

#### **9. Machine Learning Wordlist Optimization**
```python
class MLWordlistOptimizer:
    def __init__(self):
        self.model = self.load_trained_model()
        
    def optimize_wordlist(self, domain, found_subdomains):
        """Use ML to predict likely subdomains"""
        # Analyze patterns in found subdomains
        # Predict most likely candidates
        # Reduce wordlist from 100k to 10k most relevant
        pass
        
    def learn_from_results(self, domain, wordlist, results):
        """Continuously improve predictions"""
        # Update model with successful findings
        pass
```

#### **10. Recursive Discovery Engine**
```python
class RecursiveDiscovery:
    async def recursive_scan(self, initial_subdomains):
        """Recursively discover subdomains of subdomains"""
        all_subdomains = set(initial_subdomains)
        
        for subdomain in initial_subdomains:
            # Scan subdomains of subdomain
            sub_results = await self.scan_subdomain(subdomain)
            all_subdomains.update(sub_results)
            
        return all_subdomains
```

### 🎯 **FASE 4: Integration & Correlation (EXPERT)**

#### **11. Port Scanning Integration**
```python
class SubdomainPortCorrelation:
    async def correlate_with_ports(self, subdomains):
        """Correlate subdomains with open ports"""
        for subdomain in subdomains:
            # Quick port scan on common ports
            open_ports = await self.quick_port_scan(subdomain)
            subdomain['open_ports'] = open_ports
            subdomain['services'] = self.identify_services(open_ports)
```

#### **12. Technology Stack Detection**
```python
class TechStackDetection:
    async def detect_technologies(self, subdomain):
        """Detect technologies running on subdomain"""
        tech_stack = {}
        
        # HTTP headers analysis
        # Response pattern matching
        # Favicon hash matching
        # JavaScript library detection
        
        return tech_stack
```

## 📊 **Performance Targets (Inspirado nas Melhores Ferramentas)**

### **Speed Benchmarks:**
- ⚡ **Passive Discovery**: <15 segundos (como Subfinder)
- ⚡ **DNS Resolution**: 1000+ concurrent queries
- ⚡ **Certificate Logs**: <30 segundos para CT scanning
- ⚡ **Complete Scan**: <5 minutos para domínio médio

### **Coverage Targets:**
- 🎯 **API Sources**: 50+ passive sources
- 🎯 **Discovery Methods**: 7 técnicas diferentes  
- 🎯 **Wordlist**: 500k+ inteligentemente otimizada
- 🎯 **Accuracy**: >95% de subdomínios únicos válidos

## 🔧 **Implementation Priority:**

### **Week 1: Core Engine**
1. ✅ Async DNS resolver with aiodns
2. ✅ Rate limiting system
3. ✅ Multiple output formats
4. ✅ Wildcard detection improvement

### **Week 2: Passive Discovery**
1. ✅ Certificate Transparency (crt.sh)
2. ✅ Basic API integrations (5-10 sources)
3. ✅ Web scraping engine
4. ✅ Result deduplication

### **Week 3: Advanced Features**
1. ✅ Permutation engine
2. ✅ Real takeover verification  
3. ✅ Threat intelligence integration
4. ✅ Technology detection

### **Week 4: Intelligence & Polish**
1. ✅ Recursive discovery
2. ✅ ML wordlist optimization
3. ✅ Comprehensive reporting
4. ✅ Performance optimization

## 🎯 **Expected Results:**

Depois destas melhorias, o Spectra Subdomain Scanner será:

- **Mais rápido** que Assetfinder (async + concurrent)
- **Mais completo** que Amass (mais técnicas integradas)  
- **Mais inteligente** que Subfinder (ML + correlation)
- **Mais preciso** que todos (real verification + intelligence)

**Meta**: Tornar-se a **referência em subdomain scanning** da comunidade de segurança! 🚀