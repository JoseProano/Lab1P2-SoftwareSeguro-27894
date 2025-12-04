"""
HTML Report Generator for Vulnerability Scanner
Genera reporte HTML interactivo con gráficos y detalles
"""
import json
import numpy as np
import joblib
from pathlib import Path
from loguru import logger
from typing import Dict, List
import re
from datetime import datetime


class ASTFeatureExtractor:
    """Extractor de features (mismo que production_scanner.py)"""
    
    @staticmethod
    def extract_ast_features(code: str) -> np.ndarray:
        """Extrae 28 features estructurales"""
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


class HTMLReportScanner:
    """Scanner con generación de reporte HTML"""
    
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
        self.ast_extractor = ASTFeatureExtractor()
        
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
    
    def scan_code(self, code: str) -> Dict:
        X = self.extract_features(code)
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
        
        cwe_probas = self.cwe_classifier.predict_proba(X)[0]
        cwe_idx = np.argmax(cwe_probas)
        cwe_confidence = float(cwe_probas[cwe_idx])
        cwe_id = self.cwe_encoder.classes_[cwe_idx]
        
        return {
            'vulnerable': True,
            'confidence': float(vuln_proba),
            'cwe_confidence': cwe_confidence,
            'cwe_id': cwe_id,
            'severity': self.CWE_SEVERITY.get(cwe_id, 'MEDIUM'),
            'type': self.CWE_NAMES.get(cwe_id, 'Unknown Vulnerability')
        }
    
    def scan_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]:
        if extensions is None:
            extensions = ['.py', '.js', '.java', '.php', '.rb', '.go', '.ts', '.jsx', '.tsx']
        
        dir_path = Path(directory)
        all_vulnerabilities = []
        
        for ext in extensions:
            files = list(dir_path.rglob(f'*{ext}'))
            logger.info(f"Scanning {len(files)} {ext} files...")
            
            for file_path in files:
                vulns = self.scan_file(file_path)
                all_vulnerabilities.extend(vulns)
        
        return all_vulnerabilities
    
    def scan_file(self, file_path: str, chunk_size: int = 20) -> List[Dict]:
        file_path = Path(file_path)
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        vulnerabilities = []
        
        for start_line in range(0, len(lines), chunk_size):
            end_line = min(start_line + chunk_size, len(lines))
            chunk = ''.join(lines[start_line:end_line])
            
            if not chunk.strip():
                continue
            
            result = self.scan_code(chunk)
            
            if result['vulnerable']:
                result['file'] = str(file_path)
                result['line_start'] = start_line + 1
                result['line_end'] = end_line
                result['code_snippet'] = chunk
                vulnerabilities.append(result)
        
        return vulnerabilities
    
    def generate_html_report(self, vulnerabilities: List[Dict], output_file: str):
        """Genera reporte HTML interactivo"""
        
        # Stats
        total = len(vulnerabilities)
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        by_cwe = {}
        by_file = {}
        
        for vuln in vulnerabilities:
            severity = vuln['severity']
            by_severity[severity].append(vuln)
            
            cwe_id = vuln['cwe_id']
            by_cwe[cwe_id] = by_cwe.get(cwe_id, 0) + 1
            
            file_name = Path(vuln['file']).name
            by_file[file_name] = by_file.get(file_name, 0) + 1
        
        # HTML Template
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; font-size: 1.1em; }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .stat-card .label {{ 
            color: #666;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 1px;
        }}
        
        .severity-CRITICAL {{ color: #e74c3c; }}
        .severity-HIGH {{ color: #e67e22; }}
        .severity-MEDIUM {{ color: #f39c12; }}
        .severity-LOW {{ color: #3498db; }}
        
        .content {{ padding: 30px; }}
        
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        
        .chart-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }}
        .chart {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .vulnerability {{
            background: white;
            border-left: 5px solid;
            margin-bottom: 20px;
            border-radius: 5px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .vulnerability.CRITICAL {{ border-color: #e74c3c; }}
        .vulnerability.HIGH {{ border-color: #e67e22; }}
        .vulnerability.MEDIUM {{ border-color: #f39c12; }}
        .vulnerability.LOW {{ border-color: #3498db; }}
        
        .vuln-header {{
            padding: 20px;
            background: #f8f9fa;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .vuln-title {{
            font-size: 1.3em;
            font-weight: bold;
        }}
        .vuln-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .badge-CRITICAL {{ background: #e74c3c; }}
        .badge-HIGH {{ background: #e67e22; }}
        .badge-MEDIUM {{ background: #f39c12; }}
        .badge-LOW {{ background: #3498db; }}
        
        .vuln-body {{
            padding: 20px;
        }}
        .vuln-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }}
        .meta-item {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .meta-label {{
            font-weight: bold;
            color: #666;
        }}
        
        .code-snippet {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.5;
        }}
        
        .progress-bar {{
            width: 100%;
            height: 30px;
            background: #ecf0f1;
            border-radius: 15px;
            overflow: hidden;
            margin-top: 10px;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #3498db, #2ecc71);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }}
        
        .filters {{
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            padding: 10px 20px;
            border: 2px solid #3498db;
            background: white;
            color: #3498db;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }}
        .filter-btn:hover {{
            background: #3498db;
            color: white;
        }}
        .filter-btn.active {{
            background: #3498db;
            color: white;
        }}
        
        .cwe-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        .cwe-table th {{
            background: #34495e;
            color: white;
            padding: 15px;
            text-align: left;
        }}
        .cwe-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ecf0f1;
        }}
        .cwe-table tr:hover {{
            background: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Vulnerability Report</h1>
            <p>Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
            <p>Scanner: Production-Grade BigVul Implementation v3.0</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="label">Total Vulnerabilities</div>
                <div class="number">{total}</div>
            </div>
            <div class="stat-card">
                <div class="label">Critical</div>
                <div class="number severity-CRITICAL">{len(by_severity['CRITICAL'])}</div>
            </div>
            <div class="stat-card">
                <div class="label">High</div>
                <div class="number severity-HIGH">{len(by_severity['HIGH'])}</div>
            </div>
            <div class="stat-card">
                <div class="label">Medium</div>
                <div class="number severity-MEDIUM">{len(by_severity['MEDIUM'])}</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Distribution by CWE</h2>
                <table class="cwe-table">
                    <thead>
                        <tr>
                            <th>CWE ID</th>
                            <th>Vulnerability Type</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>"""
        
        for cwe_id, count in sorted(by_cwe.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            cwe_name = self.CWE_NAMES.get(cwe_id, 'Unknown')
            html += f"""
                        <tr>
                            <td><strong>{cwe_id}</strong></td>
                            <td>{cwe_name}</td>
                            <td>{count}</td>
                            <td>
                                <div class="progress-bar">
                                    <div class="progress-fill" style="width: {percentage}%">{percentage:.1f}%</div>
                                </div>
                            </td>
                        </tr>"""
        
        html += """
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>🔍 Detailed Findings</h2>
                <div class="filters">
                    <button class="filter-btn active" onclick="filterVulnerabilities('ALL')">All</button>
                    <button class="filter-btn" onclick="filterVulnerabilities('CRITICAL')">Critical</button>
                    <button class="filter-btn" onclick="filterVulnerabilities('HIGH')">High</button>
                    <button class="filter-btn" onclick="filterVulnerabilities('MEDIUM')">Medium</button>
                </div>
                <div id="vulnerabilities">"""
        
        for i, vuln in enumerate(sorted(vulnerabilities, key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x['severity'])), 1):
            severity = vuln['severity']
            html += f"""
                    <div class="vulnerability {severity}" data-severity="{severity}">
                        <div class="vuln-header">
                            <div class="vuln-title">
                                {i}. {vuln['type']}
                            </div>
                            <span class="vuln-badge badge-{severity}">{severity}</span>
                        </div>
                        <div class="vuln-body">
                            <div class="vuln-meta">
                                <div class="meta-item">
                                    <span class="meta-label">CWE:</span>
                                    <span>{vuln['cwe_id']}</span>
                                </div>
                                <div class="meta-item">
                                    <span class="meta-label">Confidence:</span>
                                    <span>{vuln['confidence']*100:.1f}%</span>
                                </div>
                                <div class="meta-item">
                                    <span class="meta-label">File:</span>
                                    <span>{Path(vuln['file']).name}</span>
                                </div>
                                <div class="meta-item">
                                    <span class="meta-label">Lines:</span>
                                    <span>{vuln['line_start']}-{vuln['line_end']}</span>
                                </div>
                            </div>
                            <div class="meta-item" style="margin-bottom: 15px;">
                                <span class="meta-label">Location:</span>
                                <span style="font-family: monospace; font-size: 0.9em;">{vuln['file']}</span>
                            </div>
                            <details>
                                <summary style="cursor: pointer; font-weight: bold; margin-bottom: 10px;">View Code Snippet</summary>
                                <pre class="code-snippet">{vuln['code_snippet'][:500]}</pre>
                            </details>
                        </div>
                    </div>"""
        
        html += """
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function filterVulnerabilities(severity) {
            const vulnerabilities = document.querySelectorAll('.vulnerability');
            const buttons = document.querySelectorAll('.filter-btn');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            vulnerabilities.forEach(vuln => {
                if (severity === 'ALL' || vuln.dataset.severity === severity) {
                    vuln.style.display = 'block';
                } else {
                    vuln.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>"""
        
        # Guardar
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"✅ HTML report saved to: {output_file}")


def main():
    scanner = HTMLReportScanner(
        models_dir='/app/models',
        threshold=0.5
    )
    
    # Escanear todo el proyecto
    logger.info("🔍 Scanning entire project...")
    vulnerabilities = scanner.scan_directory('/app/test_samples/javaspringvulny-main')
    
    logger.info(f"✅ Found {len(vulnerabilities)} vulnerabilities")
    
    # Generar HTML
    scanner.generate_html_report(
        vulnerabilities,
        '/app/reports/vulnerability_report.html'
    )
    
    logger.info("✅ Done!")


if __name__ == '__main__':
    main()
