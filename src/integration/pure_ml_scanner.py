#!/usr/bin/env python3
"""
Pure ML Vulnerability Scanner
Sin filtros agresivos, deja que el ML detecte vulnerabilidades
"""

import numpy as np
import joblib
import re
from pathlib import Path
from typing import Dict, List
from loguru import logger
import json
from datetime import datetime

class PureMLScanner:
    """Scanner basado puramente en ML con threshold bajo para máxima detección"""
    
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
    
    def __init__(self, threshold: float = 0.4):  # Threshold balanceado
        self.threshold = threshold
        logger.info(f"Loading ML models (threshold: {threshold})...")
        
        model_dir = Path('/app/models')
        self.vulnerability_detector = joblib.load(model_dir / 'production_vulnerability_detector.joblib')
        self.cwe_classifier = joblib.load(model_dir / 'production_cwe_classifier.joblib')
        self.vectorizer = joblib.load(model_dir / 'production_vectorizer.joblib')
        self.scaler = joblib.load(model_dir / 'production_scaler.joblib')
        self.cwe_encoder = joblib.load(model_dir / 'production_cwe_encoder.joblib')
        
        logger.info("✅ Models loaded")
    
    def extract_ast_features(self, code: str) -> np.ndarray:
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
    
    def extract_features(self, code: str) -> np.ndarray:
        """Combina AST + TF-IDF"""
        ast_features = self.extract_ast_features(code)
        ast_scaled = self.scaler.transform(ast_features.reshape(1, -1))
        tfidf_features = self.vectorizer.transform([code]).toarray()
        combined = np.hstack([ast_scaled, tfidf_features])
        return combined
    
    def scan_code(self, code: str) -> Dict:
        """Scan con ML + validación mínima"""
        
        # Solo filtrar código completamente vacío o solo whitespace/braces
        stripped = code.strip()
        if len(stripped) < 5 or re.match(r'^[\s\}]+$', stripped):
            return {'vulnerable': False, 'reason': 'Empty/braces only', 'cwe_id': 'SAFE'}
        
        # ML prediction
        X = self.extract_features(code)
        vuln_proba = self.vulnerability_detector.predict_proba(X)[0][1]
        
        if vuln_proba < self.threshold:
            return {
                'vulnerable': False,
                'confidence': float(1 - vuln_proba),
                'cwe_id': 'SAFE'
            }
        
        # Clasificar CWE
        cwe_probas = self.cwe_classifier.predict_proba(X)[0]
        cwe_idx = np.argmax(cwe_probas)
        cwe_confidence = float(cwe_probas[cwe_idx])
        cwe_id = self.cwe_encoder.classes_[cwe_idx]
        
        # Validación adicional: si es XSS pero solo tiene getters simples, descartar
        if cwe_id == 'CWE-79':
            if re.match(r'^\s*public\s+\w+\s+get\w+\(\)\s*\{\s*return\s+\w+;\s*\}\s*$', code, re.MULTILINE):
                return {'vulnerable': False, 'reason': 'Simple getter', 'cwe_id': 'SAFE'}
            if 'model.addAttribute' in code and 'innerHTML' not in code and 'eval' not in code:
                # Si SOLO tiene model.addAttribute y alta confianza ML, podría ser legítimo
                if cwe_confidence < 0.6:  # Baja confianza en clasificación
                    return {'vulnerable': False, 'reason': 'model.addAttribute low confidence', 'cwe_id': 'SAFE'}
        
        return {
            'vulnerable': True,
            'confidence': float(vuln_proba),
            'cwe_confidence': cwe_confidence,
            'cwe_id': cwe_id,
            'severity': self.CWE_SEVERITY.get(cwe_id, 'MEDIUM'),
            'type': self.CWE_NAMES.get(cwe_id, 'Unknown'),
            'detection_method': 'ML-based'
        }
    
    def scan_file(self, file_path: Path, chunk_size: int = 50) -> List[Dict]:
        """Escanea archivo con chunks MÁS GRANDES para mejor contexto"""
        try:
            code = file_path.read_text(encoding='utf-8', errors='ignore')
        except:
            return []
        
        vulnerabilities = []
        lines = code.split('\n')
        
        # Chunks más grandes con overlap significativo
        step = chunk_size // 3  # 66% overlap para no perder contexto
        
        for i in range(0, len(lines), step):
            chunk = '\n'.join(lines[i:i + chunk_size])
            if not chunk.strip():
                continue
            
            result = self.scan_code(chunk)
            
            if result.get('vulnerable'):
                vulnerabilities.append({
                    'file': file_path.name,
                    'full_path': str(file_path),
                    'lines': f"{i+1}-{min(i+chunk_size, len(lines))}",
                    'code_snippet': chunk[:300],
                    **result
                })
        
        # Deduplicar por archivo + CWE (mantener el de mayor confianza)
        dedup = {}
        for v in vulnerabilities:
            key = (v['file'], v['cwe_id'])
            if key not in dedup or v['confidence'] > dedup[key]['confidence']:
                dedup[key] = v
        
        return list(dedup.values())
    
    def scan_directory(self, directory: Path, extensions: List[str]) -> List[Dict]:
        """Escanea directorio completo"""
        all_vulnerabilities = []
        
        for ext in extensions:
            files = list(directory.rglob(f'*.{ext}'))
            logger.info(f"Scanning {len(files)} .{ext} files...")
            
            for file_path in files:
                vulns = self.scan_file(file_path)
                all_vulnerabilities.extend(vulns)
        
        return all_vulnerabilities


def generate_html_report(vulnerabilities: List[Dict], output_path: Path):
    """Genera reporte HTML simple"""
    
    # Estadísticas
    total = len(vulnerabilities)
    by_severity = {
        'CRITICAL': [v for v in vulnerabilities if v.get('severity') == 'CRITICAL'],
        'HIGH': [v for v in vulnerabilities if v.get('severity') == 'HIGH'],
        'MEDIUM': [v for v in vulnerabilities if v.get('severity') == 'MEDIUM'],
        'LOW': [v for v in vulnerabilities if v.get('severity') == 'LOW'],
    }
    
    by_cwe = {}
    for v in vulnerabilities:
        cwe = v.get('cwe_id', 'Unknown')
        if cwe not in by_cwe:
            by_cwe[cwe] = []
        by_cwe[cwe].append(v)
    
    # HTML
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ML Vulnerability Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 30px; text-align: center; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-card .number {{ font-size: 3em; font-weight: bold; }}
        .CRITICAL {{ color: #e74c3c; }}
        .HIGH {{ color: #e67e22; }}
        .MEDIUM {{ color: #f39c12; }}
        .vuln {{ background: white; margin: 10px 0; padding: 20px; border-left: 5px solid; border-radius: 5px; }}
        .vuln.CRITICAL {{ border-color: #e74c3c; }}
        .vuln.HIGH {{ border-color: #e67e22; }}
        .vuln.MEDIUM {{ border-color: #f39c12; }}
        .code {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; font-family: monospace; }}
        .meta {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 10px 0; }}
        .meta-item {{ padding: 5px; background: #ecf0f1; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 ML Vulnerability Scan Report</h1>
        <p>Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
        <p>Pure ML Detection - Threshold: 0.3 (Maximum Sensitivity)</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="number">{total}</div>
            <div>Total Vulnerabilities</div>
        </div>
        <div class="stat-card">
            <div class="number CRITICAL">{len(by_severity['CRITICAL'])}</div>
            <div>Critical</div>
        </div>
        <div class="stat-card">
            <div class="number HIGH">{len(by_severity['HIGH'])}</div>
            <div>High</div>
        </div>
        <div class="stat-card">
            <div class="number MEDIUM">{len(by_severity['MEDIUM'])}</div>
            <div>Medium</div>
        </div>
    </div>
    
    <h2 style="margin: 30px 0 10px 0;">📊 Distribution by CWE</h2>
    <div style="background: white; padding: 20px; border-radius: 8px;">
"""
    
    for cwe, vulns in sorted(by_cwe.items(), key=lambda x: len(x[1]), reverse=True):
        cwe_name = vulnerabilities[0].get('type', 'Unknown') if vulns else 'Unknown'
        percentage = (len(vulns) / total * 100) if total > 0 else 0
        html += f"""
        <div style="margin: 10px 0;">
            <strong>{cwe}</strong> - {cwe_name}: {len(vulns)} ({percentage:.1f}%)
            <div style="background: #ecf0f1; height: 20px; border-radius: 10px; overflow: hidden;">
                <div style="background: #3498db; height: 100%; width: {percentage}%;"></div>
            </div>
        </div>
"""
    
    html += """
    </div>
    
    <h2 style="margin: 30px 0 10px 0;">🔍 Detailed Findings</h2>
"""
    
    for i, v in enumerate(vulnerabilities, 1):
        severity = v.get('severity', 'MEDIUM')
        severity_color = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f39c12'}.get(severity, '#95a5a6')
        html += f"""
    <div class="vuln {severity}">
        <h3>{i}. {v.get('type', 'Unknown Vulnerability')} <span style="float: right; color: {severity_color}">{severity}</span></h3>
        <div class="meta">
            <div class="meta-item"><strong>CWE:</strong> {v.get('cwe_id', 'Unknown')}</div>
            <div class="meta-item"><strong>Confidence:</strong> {v.get('confidence', 0)*100:.1f}%</div>
            <div class="meta-item"><strong>File:</strong> {v.get('file', 'Unknown')}</div>
        </div>
        <div class="meta-item" style="margin: 10px 0;"><strong>Location:</strong> {v.get('full_path', 'Unknown')} (lines {v.get('lines', '?')})</div>
        <details>
            <summary style="cursor: pointer; font-weight: bold; margin: 10px 0;">View Code Snippet</summary>
            <div class="code">{v.get('code_snippet', 'N/A')}</div>
        </details>
    </div>
"""
    
    html += """
</body>
</html>
"""
    
    output_path.write_text(html, encoding='utf-8')


def main():
    logger.info("🔍 Starting ML Vulnerability Scanner...")
    logger.info(f"   Threshold: 0.4 (balanced)")
    logger.info(f"   Chunk size: 50 lines with 66% overlap")
    
    scanner = PureMLScanner(threshold=0.4)
    
    test_dir = Path('/app/test_samples/javaspringvulny-main')
    
    vulnerabilities = scanner.scan_directory(
        test_dir,
        extensions=['py', 'js', 'java', 'php', 'jsp']
    )
    
    logger.info(f"✅ Found {len(vulnerabilities)} vulnerabilities")
    
    # Agrupar por severidad
    by_severity = {
        'CRITICAL': [v for v in vulnerabilities if v.get('severity') == 'CRITICAL'],
        'HIGH': [v for v in vulnerabilities if v.get('severity') == 'HIGH'],
        'MEDIUM': [v for v in vulnerabilities if v.get('severity') == 'MEDIUM'],
    }
    
    logger.info(f"Severity breakdown:")
    logger.info(f"  CRITICAL: {len(by_severity['CRITICAL'])}")
    logger.info(f"  HIGH: {len(by_severity['HIGH'])}")
    logger.info(f"  MEDIUM: {len(by_severity['MEDIUM'])}")
    
    # Generar reporte
    output_path = Path('/app/reports/final_ml_scan_report.html')
    generate_html_report(vulnerabilities, output_path)
    logger.info(f"✅ HTML report: {output_path}")
    
    # JSON
    json_output = {
        'scan_date': datetime.now().isoformat(),
        'threshold': 0.4,
        'chunk_size': 50,
        'total_vulnerabilities': len(vulnerabilities),
        'by_severity': {k: len(v) for k, v in by_severity.items()},
        'vulnerabilities': vulnerabilities
    }
    
    json_path = Path('/app/reports/final_ml_scan_results.json')
    json_path.write_text(json.dumps(json_output, indent=2))
    logger.info(f"✅ JSON results: {json_path}")
    
    logger.info("✅ SCAN COMPLETE!")


if __name__ == '__main__':
    main()
