#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para adicionar instruções de teste faltantes no Basic Vulnerability Scanner
"""

import re

def add_missing_instructions():
    """Adiciona instruções de teste para vulnerabilidades que ainda não têm."""
    
    # Lê o arquivo atual
    with open('spectra/modules/basic_vulnerability_scanner.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Padrões para encontrar vulnerabilidades sem test_instructions
    patterns_to_fix = [
        # Security Headers sem instruções
        (
            r'(self\.vulnerabilities\.append\(Vulnerability\(\s*type=VulnerabilityType\.SECURITY_HEADERS,.*?confidence=0\.9)\s*\)\)',
            r'\1,\n                        test_instructions=self._get_test_instructions(VulnerabilityType.SECURITY_HEADERS, self.base_url)\n                    ))'
        ),
        # Clickjacking sem instruções
        (
            r'(self\.vulnerabilities\.append\(Vulnerability\(\s*type=VulnerabilityType\.CLICKJACKING,.*?confidence=0\.[89])\s*\)\)',
            r'\1,\n                    test_instructions=self._get_test_instructions(VulnerabilityType.CLICKJACKING, self.base_url)\n                ))'
        ),
        # CSP sem instruções
        (
            r'(self\.vulnerabilities\.append\(Vulnerability\(\s*type=VulnerabilityType\.CONTENT_SECURITY_POLICY,.*?confidence=0\.[78])\s*\)\)',
            r'\1,\n                        test_instructions=self._get_test_instructions(VulnerabilityType.CONTENT_SECURITY_POLICY, self.base_url)\n                    ))'
        ),
        # Input Validation sem instruções
        (
            r'(self\.vulnerabilities\.append\(Vulnerability\(\s*type=VulnerabilityType\.INPUT_VALIDATION,.*?confidence=0\.[68])\s*\)\)',
            r'\1,\n                    test_instructions=self._get_test_instructions(VulnerabilityType.INPUT_VALIDATION, action_url, field_name, payload)\n                ))'
        )
    ]
    
    # Aplica as correções
    for pattern, replacement in patterns_to_fix:
        content = re.sub(pattern, replacement, content, flags=re.DOTALL | re.MULTILINE)
    
    # Salva o arquivo modificado
    with open('spectra/modules/basic_vulnerability_scanner.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("✅ Instruções de teste adicionadas com sucesso!")

if __name__ == "__main__":
    add_missing_instructions()