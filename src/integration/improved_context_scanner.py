"""
Improved Scanner con Context-Aware Filtering
Reduce false positives mediante análisis de contexto
"""
import numpy as np
import joblib
from pathlib import Path
from loguru import logger
from typing import Dict, List
import re
from datetime import datetime


class ImprovedASTFeatureExtractor:
    """Extractor mejorado con detección de false positives"""
    
    @staticmethod
    def is_spring_config(code: str) -> bool:
        """Detecta archivos de configuración Spring Boot"""
        config_patterns = [
            r'@Configuration',
            r'@Bean\s+public',
            r'@EnableJpaRepositories',
            r'@ComponentScan',
            r'@SpringBootApplication'
        ]
        return any(re.search(p, code) for p in config_patterns)
    
    @staticmethod
    def is_safe_template_rendering(code: str) -> bool:
        """Detecta rendering seguro de templates (Thymeleaf/Spring MVC)"""
        safe_patterns = [
            r'model\.addAttribute\(',
            r'return\s+"[\w\-]+";\s*$',  # return "template-name";
            r'ModelAndView',
        ]
        # Si solo tiene model.addAttribute sin innerHTML/eval/exec, es seguro
        has_model_add = 'model.addAttribute' in code
        has_dangerous = any(d in code.lower() for d in ['innerhtml', 'eval(', 'exec('])
        return has_model_add and not has_dangerous
    
    @staticmethod
    def is_safe_getter_or_simple_return(code: str) -> bool:
        """Detecta getters simples, setters o returns de strings literales"""
        safe_method_patterns = [
            r'^\s*public\s+\w+\s+get\w+\(\)\s*\{\s*return\s+\w+;\s*\}\s*$',  # public String getName() { return name; }
            r'^\s*return\s+"[\w\-]+";\s*$',  # return "index";
            r'^\s*\}\s*$',  # Solo closing brace
        ]
        return any(re.search(p, code, re.MULTILINE) for p in safe_method_patterns)
    
    @staticmethod
    def is_entity_class(code: str) -> bool:
        """Detecta clases JPA Entity (no tienen lógica vulnerable)"""
        entity_patterns = [
            r'@Entity',
            r'@Table',
            r'@Id\s+@GeneratedValue',
            r'@Data\s+@Builder',  # Lombok
        ]
        return any(re.search(p, code) for p in entity_patterns)
    
    @staticmethod
    def has_real_sql_injection(code: str) -> bool:
        """Detecta SQL injection REAL (concatenación de strings en queries)"""
        # Patrón: query string concatenado con variables
        sql_injection_patterns = [
            r'(select|insert|update|delete|drop)\s+.*\+\s*\w+',  # SELECT ... + variable
            r'=\s*["\'].*["\'].*\+',  # query = "..." + 
            r'executeQuery\(["\'].*\+',  # executeQuery("..." +
            r'createStatement\(\).*executeQuery\(',  # Statement (no PreparedStatement)
        ]
        return any(re.search(p, code, re.IGNORECASE) for p in sql_injection_patterns)
    
    @staticmethod
    def has_real_command_injection(code: str) -> bool:
        """Detecta command injection REAL"""
        cmd_patterns = [
            r'Runtime\.getRuntime\(\)\.exec\(["\'].*\+',
            r'ProcessBuilder.*\+',
            r'exec\(["\'].*\+',
        ]
        return any(re.search(p, code) for p in cmd_patterns)
    
    @staticmethod
    def extract_ast_features(code: str) -> np.ndarray:
        """28 features estructurales"""
        features = []
        
        features.append(len(code))
        features.append(len(code.split('\n')))
        features.append(len(code.split()))
        
        control_keywords = ['if', 'else', 'for', 'while', 'switch', 'case', 'try', 'catch', 'finally']
        features.append(sum(code.lower().count(kw) for kw in control_keywords))
        
        features.append(code.count('('))
        features.append(code.count('.'))
        features.append(code.count('+'))
        features.append(code.count('f"') + code.count("f'") + code.count('`'))
        features.append(code.count('"') + code.count("'"))
        
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'where', 'from']
        features.append(sum(code.lower().count(kw) for kw in sql_keywords))
        
        exec_patterns = ['exec', 'eval', 'system', 'popen', 'subprocess', 'runtime', 'processbuilder', 'shell']
        features.append(sum(code.lower().count(pat) for pat in exec_patterns))
        
        file_ops = ['open', 'file', 'read', 'write', 'path', 'sendfile', 'readfile']
        features.append(sum(code.lower().count(op) for op in file_ops))
        
        crypto_weak = ['md5', 'sha1', 'des', 'rc4']
        crypto_strong = ['sha256', 'sha512', 'bcrypt', 'argon2', 'aes256']
        features.append(sum(code.lower().count(w) for w in crypto_weak))
        features.append(sum(code.lower().count(s) for s in crypto_strong))
        
        sanitize_keywords = ['escape', 'sanitize', 'validate', 'filter', 'whitelist', 'prepare', 'parameterized']
        features.append(sum(code.lower().count(kw) for kw in sanitize_keywords))
        
        hardcoded_patterns = [
            r'password\s*=\s*["\']',
            r'api[_-]?key\s*=\s*["\']',
            r'secret\s*=\s*["\']',
            r'token\s*=\s*["\'][a-zA-Z0-9]+',
        ]
        features.append(sum(bool(re.search(pat, code, re.IGNORECASE)) for pat in hardcoded_patterns))
        
        input_sources = ['request', 'input', 'argv', 'query', 'params', 'form', 'body', 'cookie', 'header']
        features.append(sum(code.lower().count(src) for src in input_sources))
        
        dangerous_sinks = ['innerhtml', 'eval', 'exec', 'system', 'query', 'execute']
        features.append(sum(code.lower().count(sink) for sink in dangerous_sinks))
        
        type_keywords = ['int', 'str', 'bool', 'float', 'string', 'number', 'boolean']
        features.append(sum(code.lower().count(t) for t in type_keywords))
        
        features.append(code.lower().count('try'))
        features.append(code.lower().count('except') + code.lower().count('catch'))
        
        env_patterns = ['getenv', 'process.env', 'os.environ', 'system.getenv']
        features.append(sum(code.lower().count(env) for env in env_patterns))
        
        deser_patterns = ['pickle', 'unserialize', 'deserialize', 'readobject', 'loads']
        features.append(sum(code.lower().count(d) for d in deser_patterns))
        
        xml_patterns = ['xml', 'etree', 'documentbuilder', 'saxparser']
        features.append(sum(code.lower().count(x) for x in xml_patterns))
        
        security_markers = ['@csrf', '@authorize', '@authenticate', '@secure', '@validated']
        features.append(sum(code.lower().count(m) for m in security_markers))
        
        features.append(code.count('re.') + code.count('regex') + code.count('/^'))
        features.append(code.count('//') + code.count('#'))
        features.append(code.count('/*') + code.count('"""'))
        
        return np.array(features, dtype=np.float64)


class ImprovedScanner:
    """Scanner con filtrado de false positives"""
    
    CWE_SEVERITY = {
        'CWE-89': 'CRITICAL',
        'CWE-78': 'CRITICAL',
        'CWE-94': 'CRITICAL',
        'CWE-79': 'HIGH',
        'CWE-22': 'HIGH',
        'CWE-502': 'HIGH',
        'CWE-798': 'HIGH',
        'CWE-611': 'MEDIUM',
        'CWE-327': 'MEDIUM',
        'CWE-352': 'MEDIUM',
    }
    
    CWE_NAMES = {
        'CWE-89': 'SQL Injection',
        'CWE-78': 'OS Command Injection',
        'CWE-79': 'Cross-Site Scripting (XSS)',
        'CWE-22': 'Path Traversal',
        'CWE-798': 'Hard-coded Credentials',
        'CWE-327': 'Weak Cryptography',
        'CWE-502': 'Insecure Deserialization',
        'CWE-352': 'Cross-Site Request Forgery',
        'CWE-611': 'XML External Entity (XXE)',
        'CWE-94': 'Code Injection'
    }
    
    def __init__(self, models_dir: str = './models', threshold: float = 0.5):
        self.models_dir = Path(models_dir)
        self.threshold = threshold
        self.ast_extractor = ImprovedASTFeatureExtractor()
        
        logger.info(f"Loading models (threshold: {threshold})...")
        
        self.vulnerability_detector = joblib.load(self.models_dir / 'production_vulnerability_detector.joblib')
        self.cwe_classifier = joblib.load(self.models_dir / 'production_cwe_classifier.joblib')
        self.vectorizer = joblib.load(self.models_dir / 'production_vectorizer.joblib')
        self.scaler = joblib.load(self.models_dir / 'production_scaler.joblib')
        self.cwe_encoder = joblib.load(self.models_dir / 'production_cwe_encoder.joblib')
        
        logger.info("✅ Models loaded")
    
    def extract_features(self, code: str) -> np.ndarray:
        ast_features = self.ast_extractor.extract_ast_features(code)
        ast_scaled = self.scaler.transform(ast_features.reshape(1, -1))
        tfidf_features = self.vectorizer.transform([code]).toarray()
        return np.hstack([ast_scaled, tfidf_features])
    
    def scan_code_with_context(self, code: str, file_path: str = "") -> Dict:
        """Scan con análisis de contexto para reducir false positives"""
        
        # Filtrar chunks vacíos o solo con whitespace/braces
        code_stripped = code.strip()
        if not code_stripped or len(code_stripped) < 10:
            return {'vulnerable': False, 'reason': 'Too short/empty', 'cwe_id': 'SAFE'}
        
        # Filtrar chunks que solo tienen closing braces
        if re.match(r'^[\s\}]+$', code_stripped):
            return {'vulnerable': False, 'reason': 'Only closing braces', 'cwe_id': 'SAFE'}
        
        # Pre-filtros de false positives
        if self.ast_extractor.is_spring_config(code):
            return {'vulnerable': False, 'reason': 'Spring Configuration', 'cwe_id': 'SAFE'}
        
        if self.ast_extractor.is_entity_class(code):
            return {'vulnerable': False, 'reason': 'JPA Entity', 'cwe_id': 'SAFE'}
        
        if self.ast_extractor.is_safe_template_rendering(code):
            return {'vulnerable': False, 'reason': 'Safe Template Rendering', 'cwe_id': 'SAFE'}
        
        if self.ast_extractor.is_safe_getter_or_simple_return(code):
            return {'vulnerable': False, 'reason': 'Safe getter/return', 'cwe_id': 'SAFE'}
        
        # Detección específica de vulnerabilidades reales
        if self.ast_extractor.has_real_sql_injection(code):
            return {
                'vulnerable': True,
                'confidence': 0.95,
                'cwe_id': 'CWE-89',
                'severity': 'CRITICAL',
                'type': 'SQL Injection',
                'detection_method': 'Pattern-based'
            }
        
        if self.ast_extractor.has_real_command_injection(code):
            return {
                'vulnerable': True,
                'confidence': 0.95,
                'cwe_id': 'CWE-78',
                'severity': 'CRITICAL',
                'type': 'OS Command Injection',
                'detection_method': 'Pattern-based'
            }
        
        # Si no hay patrones específicos, usar ML
        X = self.extract_features(code)
        vuln_proba = self.vulnerability_detector.predict_proba(X)[0][1]
        
        # Threshold más alto para ML (más conservador)
        ml_threshold = max(self.threshold, 0.7)
        
        if vuln_proba < ml_threshold:
            return {'vulnerable': False, 'confidence': float(1 - vuln_proba), 'cwe_id': 'SAFE'}
        
        cwe_probas = self.cwe_classifier.predict_proba(X)[0]
        cwe_idx = np.argmax(cwe_probas)
        cwe_confidence = float(cwe_probas[cwe_idx])
        cwe_id = self.cwe_encoder.classes_[cwe_idx]
        
        # Validar CWE con contexto
        if cwe_id == 'CWE-79' and self.ast_extractor.is_safe_template_rendering(code):
            return {'vulnerable': False, 'reason': 'False XSS (safe template)', 'cwe_id': 'SAFE'}
        
        return {
            'vulnerable': True,
            'confidence': float(vuln_proba),
            'cwe_confidence': cwe_confidence,
            'cwe_id': cwe_id,
            'severity': self.CWE_SEVERITY.get(cwe_id, 'MEDIUM'),
            'type': self.CWE_NAMES.get(cwe_id, 'Unknown'),
            'detection_method': 'ML-based'
        }
    
    def scan_file(self, file_path: str, chunk_size: int = 30) -> List[Dict]:
        """Escanea archivo con chunks más grandes"""
        file_path = Path(file_path)
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        vulnerabilities = []
        
        for start_line in range(0, len(lines), chunk_size):
            end_line = min(start_line + chunk_size, len(lines))
            chunk = ''.join(lines[start_line:end_line])
            
            if not chunk.strip():
                continue
            
            result = self.scan_code_with_context(chunk, str(file_path))
            
            if result.get('vulnerable'):
                result['file'] = str(file_path)
                result['line_start'] = start_line + 1
                result['line_end'] = end_line
                result['code_snippet'] = chunk
                vulnerabilities.append(result)
        
        return vulnerabilities
    
    def scan_directory(self, directory: str) -> List[Dict]:
        """Escanea directorio"""
        extensions = ['.py', '.js', '.java', '.php']
        dir_path = Path(directory)
        all_vulnerabilities = []
        
        for ext in extensions:
            files = list(dir_path.rglob(f'*{ext}'))
            logger.info(f"Scanning {len(files)} {ext} files...")
            
            for file_path in files:
                vulns = self.scan_file(file_path)
                all_vulnerabilities.extend(vulns)
        
        return all_vulnerabilities


def main():
    from html_report_scanner import HTMLReportScanner
    
    scanner = ImprovedScanner(
        models_dir='/app/models',
        threshold=0.5  # Threshold bajo, pero con context filtering
    )
    
    logger.info("🔍 Scanning with improved context-aware filtering...")
    vulnerabilities = scanner.scan_directory('/app/test_samples/javaspringvulny-main')
    
    logger.info(f"✅ Found {len(vulnerabilities)} REAL vulnerabilities (after filtering)")
    
    # Stats
    by_method = {}
    for v in vulnerabilities:
        method = v.get('detection_method', 'Unknown')
        by_method[method] = by_method.get(method, 0) + 1
    
    logger.info("Detection methods:")
    for method, count in by_method.items():
        logger.info(f"  {method}: {count}")
    
    # Generar HTML
    html_scanner = HTMLReportScanner(models_dir='/app/models', threshold=0.5)
    html_scanner.generate_html_report(
        vulnerabilities,
        '/app/reports/improved_vulnerability_report.html'
    )
    
    logger.info("✅ Done!")


if __name__ == '__main__':
    main()
