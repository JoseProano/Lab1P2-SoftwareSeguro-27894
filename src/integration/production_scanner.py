"""
Production Vulnerability Scanner
Usa modelos entrenados con estrategia BigVul/SARD
Features: AST-based + TF-IDF, weighted loss, threshold ajustable
"""
import numpy as np
import joblib
from pathlib import Path
from loguru import logger
import json
import sys
from typing import Dict, List, Tuple
import re


class ASTFeatureExtractor:
    """Mismo extractor usado en training"""
    
    @staticmethod
    def extract_ast_features(code: str) -> np.ndarray:
        """Extrae 30 features estructurales"""
        features = []
        
        # 1-3: Longitud y complejidad
        features.append(len(code))
        features.append(len(code.split('\n')))
        features.append(len(code.split()))
        
        # 4: Control flow
        control_keywords = ['if', 'else', 'for', 'while', 'switch', 'case', 'try', 'catch', 'finally']
        features.append(sum(code.lower().count(kw) for kw in control_keywords))
        
        # 5-6: Calls y métodos
        features.append(code.count('('))
        features.append(code.count('.'))
        
        # 7-9: String operations
        features.append(code.count('+'))
        features.append(code.count('f"') + code.count("f'") + code.count('`'))
        features.append(code.count('"') + code.count("'"))
        
        # 10: SQL patterns
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'where', 'from']
        features.append(sum(code.lower().count(kw) for kw in sql_keywords))
        
        # 11: Command execution
        exec_patterns = ['exec', 'eval', 'system', 'popen', 'subprocess', 'runtime', 'processbuilder', 'shell']
        features.append(sum(code.lower().count(pat) for pat in exec_patterns))
        
        # 12: File operations
        file_ops = ['open', 'file', 'read', 'write', 'path', 'sendfile', 'readfile']
        features.append(sum(code.lower().count(op) for op in file_ops))
        
        # 13-14: Crypto
        crypto_weak = ['md5', 'sha1', 'des', 'rc4']
        crypto_strong = ['sha256', 'sha512', 'bcrypt', 'argon2', 'aes256']
        features.append(sum(code.lower().count(w) for w in crypto_weak))
        features.append(sum(code.lower().count(s) for s in crypto_strong))
        
        # 15: Sanitization
        sanitize_keywords = ['escape', 'sanitize', 'validate', 'filter', 'whitelist', 'prepare', 'parameterized']
        features.append(sum(code.lower().count(kw) for kw in sanitize_keywords))
        
        # 16: Hard-coded credentials
        hardcoded_patterns = [
            r'password\s*=\s*["\']',
            r'api[_-]?key\s*=\s*["\']',
            r'secret\s*=\s*["\']',
            r'token\s*=\s*["\'][a-zA-Z0-9]+',
        ]
        features.append(sum(bool(re.search(pat, code, re.IGNORECASE)) for pat in hardcoded_patterns))
        
        # 17: Input sources
        input_sources = ['request', 'input', 'argv', 'query', 'params', 'form', 'body', 'cookie', 'header']
        features.append(sum(code.lower().count(src) for src in input_sources))
        
        # 18: Dangerous sinks
        dangerous_sinks = ['innerhtml', 'eval', 'exec', 'system', 'query', 'execute']
        features.append(sum(code.lower().count(sink) for sink in dangerous_sinks))
        
        # 19: Type safety
        type_keywords = ['int', 'str', 'bool', 'float', 'string', 'number', 'boolean']
        features.append(sum(code.lower().count(t) for t in type_keywords))
        
        # 20-21: Exception handling
        features.append(code.lower().count('try'))
        features.append(code.lower().count('except') + code.lower().count('catch'))
        
        # 22: Environment variables
        env_patterns = ['getenv', 'process.env', 'os.environ', 'system.getenv']
        features.append(sum(code.lower().count(env) for env in env_patterns))
        
        # 23: Deserialization
        deser_patterns = ['pickle', 'unserialize', 'deserialize', 'readobject', 'loads']
        features.append(sum(code.lower().count(d) for d in deser_patterns))
        
        # 24: XML processing
        xml_patterns = ['xml', 'etree', 'documentbuilder', 'saxparser']
        features.append(sum(code.lower().count(x) for x in xml_patterns))
        
        # 25: Security markers
        security_markers = ['@csrf', '@authorize', '@authenticate', '@secure', '@validated']
        features.append(sum(code.lower().count(m) for m in security_markers))
        
        # 26: Regex (validación)
        features.append(code.count('re.') + code.count('regex') + code.count('/^'))
        
        # 27-28: Comments
        features.append(code.count('//') + code.count('#'))
        features.append(code.count('/*') + code.count('"""'))
        
        return np.array(features, dtype=np.float64)


class ProductionScanner:
    """Scanner de producción con modelos mejorados"""
    
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
    
    def __init__(self, models_dir: str = './models', threshold: float = 0.5):
        """
        threshold: Umbral de confianza (0.0-1.0)
            - 0.3: Muy sensible (más detecciones, más falsos positivos)
            - 0.5: Balanceado (recomendado para producción)
            - 0.7: Conservador (menos detecciones, más precisión)
        """
        self.models_dir = Path(models_dir)
        self.threshold = threshold
        self.ast_extractor = ASTFeatureExtractor()
        
        logger.info(f"🔧 Loading production models from {self.models_dir}")
        logger.info(f"   Detection threshold: {threshold}")
        
        # Load models
        try:
            self.vulnerability_detector = joblib.load(
                self.models_dir / 'production_vulnerability_detector.joblib'
            )
            self.cwe_classifier = joblib.load(
                self.models_dir / 'production_cwe_classifier.joblib'
            )
            self.vectorizer = joblib.load(
                self.models_dir / 'production_vectorizer.joblib'
            )
            self.scaler = joblib.load(
                self.models_dir / 'production_scaler.joblib'
            )
            self.cwe_encoder = joblib.load(
                self.models_dir / 'production_cwe_encoder.joblib'
            )
            logger.info("✅ Models loaded successfully")
        except FileNotFoundError as e:
            logger.error(f"❌ Model files not found: {e}")
            logger.error("   Run train_production_model.py first!")
            raise
    
    def extract_features(self, code: str) -> np.ndarray:
        """Extrae features híbridos (AST + TF-IDF)"""
        # AST features
        ast_features = self.ast_extractor.extract_ast_features(code)
        ast_scaled = self.scaler.transform(ast_features.reshape(1, -1))
        
        # TF-IDF features
        tfidf_features = self.vectorizer.transform([code]).toarray()
        
        # Combine
        combined = np.hstack([ast_scaled, tfidf_features])
        return combined
    
    def scan_code(self, code: str) -> Dict:
        """
        Escanea código y retorna vulnerabilidades detectadas
        """
        # Extract features
        X = self.extract_features(code)
        
        # Step 1: Binary classification
        vuln_proba = self.vulnerability_detector.predict_proba(X)[0][1]
        is_vulnerable = vuln_proba >= self.threshold
        
        if not is_vulnerable:
            return {
                'vulnerable': False,
                'confidence': float(1 - vuln_proba),
                'cwe_id': 'SAFE',
                'severity': 'NONE',
                'type': 'Safe Code'
            }
        
        # Step 2: CWE classification
        cwe_probas = self.cwe_classifier.predict_proba(X)[0]
        cwe_idx = np.argmax(cwe_probas)
        cwe_confidence = float(cwe_probas[cwe_idx])
        cwe_id = self.cwe_encoder.classes_[cwe_idx]
        
        # Mapear CWE a tipo de vulnerabilidad
        cwe_types = {
            'CWE-89': 'SQL Injection',
            'CWE-78': 'Command Injection',
            'CWE-79': 'Cross-Site Scripting (XSS)',
            'CWE-22': 'Path Traversal',
            'CWE-798': 'Hard-coded Credentials',
            'CWE-327': 'Weak Cryptography',
            'CWE-502': 'Insecure Deserialization',
            'CWE-352': 'Cross-Site Request Forgery (CSRF)',
            'CWE-611': 'XML External Entity (XXE)',
            'CWE-94': 'Code Injection'
        }
        
        return {
            'vulnerable': True,
            'confidence': float(vuln_proba),
            'cwe_confidence': cwe_confidence,
            'cwe_id': cwe_id,
            'severity': self.CWE_SEVERITY.get(cwe_id, 'MEDIUM'),
            'type': cwe_types.get(cwe_id, 'Unknown Vulnerability')
        }
    
    def scan_file(self, file_path: str, chunk_size: int = 20) -> List[Dict]:
        """
        Escanea archivo completo dividiéndolo en chunks
        """
        logger.info(f"📄 Scanning file: {file_path}")
        
        file_path = Path(file_path)
        if not file_path.exists():
            logger.error(f"❌ File not found: {file_path}")
            return []
        
        # Read file
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        logger.info(f"   Total lines: {len(lines)}")
        
        # Scan por chunks
        vulnerabilities = []
        
        for start_line in range(0, len(lines), chunk_size):
            end_line = min(start_line + chunk_size, len(lines))
            chunk = ''.join(lines[start_line:end_line])
            
            # Skip empty chunks
            if not chunk.strip():
                continue
            
            # Scan chunk
            result = self.scan_code(chunk)
            
            if result['vulnerable']:
                result['file'] = str(file_path)
                result['line_start'] = start_line + 1
                result['line_end'] = end_line
                result['code_snippet'] = chunk[:200]  # First 200 chars
                vulnerabilities.append(result)
        
        logger.info(f"   Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def scan_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]:
        """Escanea directorio recursivamente"""
        if extensions is None:
            extensions = ['.py', '.js', '.java', '.php', '.rb', '.go', '.ts', '.jsx', '.tsx']
        
        dir_path = Path(directory)
        logger.info(f"📁 Scanning directory: {dir_path}")
        
        all_vulnerabilities = []
        
        for ext in extensions:
            files = list(dir_path.rglob(f'*{ext}'))
            logger.info(f"   Found {len(files)} {ext} files")
            
            for file_path in files:
                vulns = self.scan_file(file_path)
                all_vulnerabilities.extend(vulns)
        
        return all_vulnerabilities
    
    def generate_report(self, vulnerabilities: List[Dict], output_file: str = None):
        """Genera reporte de vulnerabilidades"""
        logger.info("=" * 60)
        logger.info("📊 VULNERABILITY SCAN REPORT")
        logger.info("=" * 60)
        
        if not vulnerabilities:
            logger.info("✅ No vulnerabilities detected!")
            return
        
        logger.info(f"Total vulnerabilities: {len(vulnerabilities)}")
        logger.info("")
        
        # Group by severity
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for vuln in vulnerabilities:
            by_severity[vuln['severity']].append(vuln)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = len(by_severity[severity])
            if count > 0:
                logger.info(f"{severity}: {count}")
        
        logger.info("")
        logger.info("Detailed Findings:")
        logger.info("-" * 60)
        
        for i, vuln in enumerate(vulnerabilities, 1):
            logger.info(f"\n{i}. {vuln['type']} ({vuln['cwe_id']})")
            logger.info(f"   Severity: {vuln['severity']}")
            logger.info(f"   Confidence: {vuln['confidence']*100:.1f}%")
            logger.info(f"   Location: {vuln['file']}:{vuln['line_start']}-{vuln['line_end']}")
            logger.info(f"   Snippet: {vuln['code_snippet'][:100]}...")
        
        # Save JSON report
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(vulnerabilities, f, indent=2)
            logger.info(f"\n💾 Report saved to: {output_file}")


def main():
    """Main scanner entry point"""
    if len(sys.argv) < 2:
        print("Usage: python production_scanner.py <file_or_directory> [threshold]")
        print("Example: python production_scanner.py ./test_samples 0.5")
        sys.exit(1)
    
    target = sys.argv[1]
    threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 0.5
    
    scanner = ProductionScanner(
        models_dir='/app/models',
        threshold=threshold
    )
    
    # Scan
    if Path(target).is_file():
        vulnerabilities = scanner.scan_file(target)
    else:
        vulnerabilities = scanner.scan_directory(target)
    
    # Report
    scanner.generate_report(
        vulnerabilities,
        output_file='/app/reports/production_scan_report.json'
    )


if __name__ == '__main__':
    main()
