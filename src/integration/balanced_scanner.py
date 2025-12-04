#!/usr/bin/env python3
"""
Balanced Vulnerability Scanner
Usa ML + Pattern-based con filtros menos agresivos
"""

import numpy as np
import joblib
import re
from pathlib import Path
from typing import Dict, List, Tuple
from loguru import logger
import json
from datetime import datetime

class BalancedScanner:
    """Scanner balanceado: detecta vulnerabilidades reales sin ser demasiado agresivo"""
    
    CWE_NAMES = {
        'CWE-89': 'SQL Injection',
        'CWE-78': 'OS Command Injection',
        'CWE-79': 'Cross-Site Scripting (XSS)',
        'CWE-22': 'Path Traversal',
        'CWE-798': 'Hard-coded Credentials',
        'CWE-327': 'Broken Cryptography',
        'CWE-502': 'Deserialization',
        'CWE-352': 'CSRF',
        'CWE-611': 'XXE',
        'CWE-94': 'Code Injection',
    }
    
    CWE_SEVERITY = {
        'CWE-89': 'CRITICAL',
        'CWE-78': 'CRITICAL',
        'CWE-94': 'CRITICAL',
        'CWE-79': 'HIGH',
        'CWE-22': 'HIGH',
        'CWE-502': 'HIGH',
        'CWE-611': 'HIGH',
        'CWE-798': 'HIGH',
        'CWE-327': 'MEDIUM',
        'CWE-352': 'MEDIUM',
    }
    
    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
        logger.info(f"Loading models (threshold: {threshold})...")
        
        model_dir = Path('/app/models')
        self.vulnerability_detector = joblib.load(model_dir / 'production_vulnerability_detector.joblib')
        self.cwe_classifier = joblib.load(model_dir / 'production_cwe_classifier.joblib')
        self.vectorizer = joblib.load(model_dir / 'production_vectorizer.joblib')
        self.scaler = joblib.load(model_dir / 'production_scaler.joblib')
        self.cwe_encoder = joblib.load(model_dir / 'production_cwe_encoder.joblib')
        
        logger.info("✅ Models loaded")
    
    @staticmethod
    def has_sql_injection_pattern(code: str) -> bool:
        """Detecta patrones comunes de SQL injection"""
        patterns = [
            r'(select|insert|update|delete|drop)\s+.*\+\s*\w+',  # SELECT ... + var
            r'=\s*["\'][^"\']*["\'].*\+',  # query = "..." + 
            r'executeQuery\s*\(["\'][^"\']*\+',  # executeQuery("..." +
            r'createStatement\(\).*executeQuery',  # Statement sin PreparedStatement
            r'query.*=.*\+.*getParameter',  # query = ... + request.getParameter
            r'query.*=.*\+.*request\.',  # query = ... + request.
        ]
        return any(re.search(p, code, re.IGNORECASE | re.MULTILINE) for p in patterns)
    
    @staticmethod
    def has_command_injection_pattern(code: str) -> bool:
        """Detecta command injection"""
        patterns = [
            r'Runtime\.getRuntime\(\)\.exec\([^)]*\+',
            r'ProcessBuilder.*\+',
            r'exec\s*\([^)]*\+',
            r'system\s*\([^)]*\+',
            r'subprocess\.call.*\+',
            r'os\.system.*\+',
        ]
        return any(re.search(p, code, re.IGNORECASE) for p in patterns)
    
    @staticmethod
    def has_xss_pattern(code: str) -> bool:
        """Detecta XSS real (no model.addAttribute)"""
        # Patrones peligrosos
        dangerous = [
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'eval\s*\([^)]*request',
            r'\.html\s*\([^)]*request',
            r'dangerouslySetInnerHTML',
        ]
        has_dangerous = any(re.search(p, code, re.IGNORECASE) for p in dangerous)
        
        # Patrones seguros (NO es XSS)
        safe = [
            r'model\.addAttribute\s*\(',
            r'return\s+"[\w\-]+";',  # return "template-name";
        ]
        has_only_safe = any(re.search(p, code) for p in safe) and not has_dangerous
        
        return has_dangerous and not has_only_safe
    
    @staticmethod
    def has_path_traversal_pattern(code: str) -> bool:
        """Detecta path traversal real"""
        patterns = [
            r'(File|Path|Paths\.get).*\+.*request',
            r'readFile.*\+.*getParameter',
            r'FileInputStream.*\+.*request',
            r'\.\./|\.\.',  # ../ o ..
        ]
        return any(re.search(p, code, re.IGNORECASE) for p in patterns)
    
    @staticmethod
    def has_hardcoded_credentials(code: str) -> bool:
        """Detecta credenciales hardcoded"""
        patterns = [
            r'password\s*=\s*["\'][^"\']{8,}["\']',  # password = "hardcoded"
            r'api[_-]?key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
            r'secret\s*=\s*["\'][a-zA-Z0-9]{16,}["\']',
            r'token\s*=\s*["\'][a-zA-Z0-9]{32,}["\']',
            r'AWS_SECRET_ACCESS_KEY',
        ]
        # Excluir ejemplos/comentarios
        if '// example' in code.lower() or '# example' in code.lower():
            return False
        return any(re.search(p, code, re.IGNORECASE) for p in patterns)
    
    @staticmethod
    def is_likely_false_positive(code: str) -> bool:
        """Detecta chunks que probablemente son falsos positivos"""
        # Muy corto o solo whitespace
        if len(code.strip()) < 15:
            return True
        
        # Solo closing braces
        if re.match(r'^[\s\}]+$', code.strip()):
            return True
        
        # Solo imports/package
        if re.match(r'^(import|package)\s+', code.strip()):
            return True
        
        # Solo comentarios
        lines = [l.strip() for l in code.split('\n') if l.strip()]
        if all(l.startswith('//') or l.startswith('#') or l.startswith('/*') or l.startswith('*') for l in lines):
            return True
        
        return False
    
    @staticmethod
    def is_spring_config_only(code: str) -> bool:
        """Detecta archivos que SOLO son configuración de Spring (sin lógica)"""
        has_config = bool(re.search(r'@Configuration|@Bean|@EnableJpa', code))
        has_logic = bool(re.search(r'(if|for|while|switch)\s*\(', code))
        has_query = bool(re.search(r'(query|execute|select|insert)', code, re.IGNORECASE))
        
        # Es config puro si tiene @Configuration pero NO tiene lógica ni queries
        return has_config and not has_logic and not has_query
    
    def extract_ast_features(self, code: str) -> np.ndarray:
        """Extrae 28 features estructurales del código"""
        features = []
        
        # Básicas
        features.append(len(code))
        features.append(len(code.split('\n')))
        features.append(len(code.split()))
        
        # Control flow
        control_keywords = ['if', 'else', 'for', 'while', 'switch', 'case', 'try', 'catch', 'finally']
        features.append(sum(code.lower().count(kw) for kw in control_keywords))
        
        # Sintaxis
        features.append(code.count('('))
        features.append(code.count('.'))
        features.append(code.count('+'))
        features.append(code.count('f"') + code.count("f'") + code.count('`'))
        features.append(code.count('"') + code.count("'"))
        
        # SQL
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'where', 'from']
        features.append(sum(code.lower().count(kw) for kw in sql_keywords))
        
        # Execution
        exec_patterns = ['exec', 'eval', 'system', 'popen', 'subprocess', 'runtime', 'processbuilder', 'shell']
        features.append(sum(code.lower().count(pat) for pat in exec_patterns))
        
        # File ops
        file_ops = ['open', 'file', 'read', 'write', 'path', 'sendfile', 'readfile']
        features.append(sum(code.lower().count(op) for op in file_ops))
        
        # Crypto
        crypto_weak = ['md5', 'sha1', 'des', 'rc4']
        crypto_strong = ['sha256', 'sha512', 'bcrypt', 'argon2', 'aes256']
        features.append(sum(code.lower().count(w) for w in crypto_weak))
        features.append(sum(code.lower().count(s) for s in crypto_strong))
        
        # Sanitization
        sanitize_keywords = ['escape', 'sanitize', 'validate', 'filter', 'whitelist', 'prepare', 'parameterized']
        features.append(sum(code.lower().count(kw) for kw in sanitize_keywords))
        
        # Hardcoded secrets
        hardcoded_patterns = [
            r'password\s*=\s*["\']',
            r'api[_-]?key\s*=\s*["\']',
            r'secret\s*=\s*["\']',
            r'token\s*=\s*["\'][a-zA-Z0-9]+',
        ]
        features.append(sum(bool(re.search(pat, code, re.IGNORECASE)) for pat in hardcoded_patterns))
        
        # Input sources
        input_sources = ['request', 'input', 'argv', 'query', 'params', 'form', 'body', 'cookie', 'header']
        features.append(sum(code.lower().count(src) for src in input_sources))
        
        # Dangerous sinks
        dangerous_sinks = ['innerhtml', 'eval', 'exec', 'system', 'query', 'execute']
        features.append(sum(code.lower().count(sink) for sink in dangerous_sinks))
        
        # Type hints
        type_keywords = ['int', 'str', 'bool', 'float', 'string', 'number', 'boolean']
        features.append(sum(code.lower().count(t) for t in type_keywords))
        
        # Error handling
        features.append(code.lower().count('try'))
        features.append(code.lower().count('except') + code.lower().count('catch'))
        
        # Environment
        env_patterns = ['getenv', 'process.env', 'os.environ', 'system.getenv']
        features.append(sum(code.lower().count(env) for env in env_patterns))
        
        # Deserialization
        deser_patterns = ['pickle', 'unserialize', 'deserialize', 'readobject', 'loads']
        features.append(sum(code.lower().count(d) for d in deser_patterns))
        
        # XML
        xml_patterns = ['xml', 'etree', 'documentbuilder', 'saxparser']
        features.append(sum(code.lower().count(x) for x in xml_patterns))
        
        # Security markers
        security_markers = ['@csrf', '@authorize', '@authenticate', '@secure', '@validated']
        features.append(sum(code.lower().count(m) for m in security_markers))
        
        # Misc
        features.append(code.count('re.') + code.count('regex') + code.count('/^'))
        features.append(code.count('//') + code.count('#'))
        features.append(code.count('/*') + code.count('"""'))
        
        return np.array(features, dtype=np.float64)
    
    def extract_features(self, code: str) -> np.ndarray:
        """Combina AST + TF-IDF features (igual que production_scanner)"""
        # AST features (28)
        ast_features = self.extract_ast_features(code)
        ast_scaled = self.scaler.transform(ast_features.reshape(1, -1))
        
        # TF-IDF features (5000)
        tfidf_features = self.vectorizer.transform([code]).toarray()
        
        # Combine (28 + 5000 = 5028)
        combined = np.hstack([ast_scaled, tfidf_features])
        return combined
    
    def scan_code(self, code: str, file_path: str = "") -> Dict:
        """Scan balanceado: pattern-based + ML"""
        
        # Pre-filtro: descartar chunks obviamente inofensivos
        if self.is_likely_false_positive(code):
            return {'vulnerable': False, 'reason': 'Likely false positive', 'cwe_id': 'SAFE'}
        
        # Filtro: archivos de configuración pura (sin lógica)
        if self.is_spring_config_only(code):
            return {'vulnerable': False, 'reason': 'Spring config only', 'cwe_id': 'SAFE'}
        
        # Detección pattern-based para vulnerabilidades críticas
        if self.has_sql_injection_pattern(code):
            return {
                'vulnerable': True,
                'confidence': 0.95,
                'cwe_id': 'CWE-89',
                'severity': 'CRITICAL',
                'type': 'SQL Injection',
                'detection_method': 'Pattern-based'
            }
        
        if self.has_command_injection_pattern(code):
            return {
                'vulnerable': True,
                'confidence': 0.95,
                'cwe_id': 'CWE-78',
                'severity': 'CRITICAL',
                'type': 'OS Command Injection',
                'detection_method': 'Pattern-based'
            }
        
        if self.has_path_traversal_pattern(code):
            return {
                'vulnerable': True,
                'confidence': 0.90,
                'cwe_id': 'CWE-22',
                'severity': 'HIGH',
                'type': 'Path Traversal',
                'detection_method': 'Pattern-based'
            }
        
        if self.has_hardcoded_credentials(code):
            return {
                'vulnerable': True,
                'confidence': 0.85,
                'cwe_id': 'CWE-798',
                'severity': 'HIGH',
                'type': 'Hard-coded Credentials',
                'detection_method': 'Pattern-based'
            }
        
        # ML para otros casos
        X = self.extract_features(code)
        vuln_proba = self.vulnerability_detector.predict_proba(X)[0][1]
        
        if vuln_proba < self.threshold:
            return {'vulnerable': False, 'confidence': float(1 - vuln_proba), 'cwe_id': 'SAFE'}
        
        # Clasificar CWE
        cwe_probas = self.cwe_classifier.predict_proba(X)[0]
        cwe_idx = np.argmax(cwe_probas)
        cwe_confidence = float(cwe_probas[cwe_idx])
        cwe_id = self.cwe_encoder.classes_[cwe_idx]
        
        # Validación adicional para XSS
        if cwe_id == 'CWE-79' and not self.has_xss_pattern(code):
            # Si ML dice XSS pero no hay patrón peligroso, reducir confianza
            if cwe_confidence < 0.8:
                return {'vulnerable': False, 'reason': 'XSS false positive', 'cwe_id': 'SAFE'}
        
        return {
            'vulnerable': True,
            'confidence': float(vuln_proba),
            'cwe_confidence': cwe_confidence,
            'cwe_id': cwe_id,
            'severity': self.CWE_SEVERITY.get(cwe_id, 'MEDIUM'),
            'type': self.CWE_NAMES.get(cwe_id, 'Unknown'),
            'detection_method': 'ML-based'
        }
    
    def scan_file(self, file_path: Path, chunk_size: int = 30) -> List[Dict]:
        """Escanea un archivo completo dividido en chunks"""
        try:
            code = file_path.read_text(encoding='utf-8', errors='ignore')
        except:
            return []
        
        vulnerabilities = []
        lines = code.split('\n')
        
        # Escanear en chunks de tamaño variable (más contexto)
        for i in range(0, len(lines), chunk_size // 2):  # Overlap 50%
            chunk = '\n'.join(lines[i:i + chunk_size])
            if not chunk.strip():
                continue
            
            result = self.scan_code(chunk, str(file_path))
            
            if result.get('vulnerable'):
                vulnerabilities.append({
                    'file': file_path.name,
                    'full_path': str(file_path),
                    'lines': f"{i+1}-{min(i+chunk_size, len(lines))}",
                    'code_snippet': chunk[:200],
                    **result
                })
        
        # Deduplicar vulnerabilidades del mismo tipo en el mismo archivo
        seen = set()
        unique_vulns = []
        for v in vulnerabilities:
            key = (v['file'], v['cwe_id'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        
        return unique_vulns
    
    def scan_directory(self, directory: Path, extensions: List[str]) -> List[Dict]:
        """Escanea un directorio completo"""
        all_vulnerabilities = []
        
        for ext in extensions:
            files = list(directory.rglob(f'*.{ext}'))
            logger.info(f"Scanning {len(files)} .{ext} files...")
            
            for file_path in files:
                vulns = self.scan_file(file_path)
                all_vulnerabilities.extend(vulns)
        
        return all_vulnerabilities


def main():
    logger.info("🔍 Scanning with BALANCED scanner (Pattern + ML)...")
    
    scanner = BalancedScanner(threshold=0.5)  # Threshold balanceado
    
    test_dir = Path('/app/test_samples/javaspringvulny-main')
    
    vulnerabilities = scanner.scan_directory(
        test_dir,
        extensions=['py', 'js', 'java', 'php']
    )
    
    logger.info(f"✅ Found {len(vulnerabilities)} vulnerabilities")
    
    # Agrupar por método de detección
    pattern_based = [v for v in vulnerabilities if v.get('detection_method') == 'Pattern-based']
    ml_based = [v for v in vulnerabilities if v.get('detection_method') == 'ML-based']
    
    logger.info(f"Detection methods:")
    logger.info(f"  Pattern-based: {len(pattern_based)}")
    logger.info(f"  ML-based: {len(ml_based)}")
    
    # Generar reporte HTML
    from html_report_scanner import HTMLReportScanner
    report_generator = HTMLReportScanner()
    
    output_path = Path('/app/reports/balanced_vulnerability_report.html')
    report_generator.generate_html_report(vulnerabilities, output_path)
    logger.info(f"✅ HTML report saved to: {output_path}")
    
    # Guardar JSON
    json_output = {
        'scan_date': datetime.now().isoformat(),
        'total_vulnerabilities': len(vulnerabilities),
        'pattern_based': len(pattern_based),
        'ml_based': len(ml_based),
        'vulnerabilities': vulnerabilities
    }
    
    json_path = Path('/app/reports/balanced_scan_results.json')
    json_path.write_text(json.dumps(json_output, indent=2))
    
    logger.info("✅ Done!")


if __name__ == '__main__':
    main()
