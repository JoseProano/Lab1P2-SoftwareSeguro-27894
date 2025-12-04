#!/usr/bin/env python3
"""
Scanner que usa modelos entrenados con CÓDIGO REAL
Aplica minería de datos para detectar vulnerabilidades
"""

import numpy as np
from pathlib import Path
from typing import List, Dict
from loguru import logger
import joblib
from datetime import datetime
import json

# Importar feature extractor del mining
import sys
sys.path.insert(0, '/app/src/models')
from real_data_mining import AdvancedFeatureExtractor

class RealCodeScanner:
    """
    Scanner basado en modelos entrenados con código REAL vulnerable
    Sin patrones hardcoded, puro ML
    """
    
    def __init__(self):
        self.models_dir = Path('/app/models')
        self.feature_extractor = AdvancedFeatureExtractor()
        
        logger.info("Loading models trained with REAL vulnerable code...")
        
        self.model = joblib.load(self.models_dir / 'real_code_vulnerability_detector.joblib')
        self.scaler = joblib.load(self.models_dir / 'real_code_scaler.joblib')
        self.label_encoder = joblib.load(self.models_dir / 'real_code_label_encoder.joblib')
        
        # Load metadata
        metadata_path = self.models_dir / 'real_code_model_metadata.json'
        if metadata_path.exists():
            self.metadata = json.loads(metadata_path.read_text())
            logger.info(f"Model type: {self.metadata.get('model_type')}")
            logger.info(f"Trained: {self.metadata.get('trained_date')}")
            logger.info(f"Data source: {self.metadata.get('data_source')}")
        
        logger.info("✅ Models loaded")
    
    def scan_code(self, code: str) -> Dict:
        """Scan código usando ML puro"""
        
        # Filtrar código vacío
        if len(code.strip()) < 20:
            return {'vulnerable': False, 'reason': 'Too short', 'label': 'SAFE'}
        
        # Extraer features (MISMO proceso que en entrenamiento)
        features = self.feature_extractor.extract_all_features(code)
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # Predecir
        prediction = self.model.predict(features_scaled)[0]
        proba = self.model.predict_proba(features_scaled)[0]
        
        # Decodificar label
        label = self.label_encoder.inverse_transform([prediction])[0]
        confidence = float(proba[prediction])
        
        if label == 'SAFE':
            return {
                'vulnerable': False,
                'label': label,
                'confidence': confidence
            }
        
        # Es vulnerable
        return {
            'vulnerable': True,
            'label': label,  # CWE-89, CWE-78, etc.
            'confidence': confidence,
            'cwe_id': label,
            'type': self.get_cwe_name(label),
            'severity': self.get_severity(label),
            'detection_method': 'ML-RealCode'
        }
    
    def get_cwe_name(self, cwe_id: str) -> str:
        """Mapeo CWE a nombre"""
        cwe_names = {
            'CWE-89': 'SQL Injection',
            'CWE-78': 'OS Command Injection',
            'CWE-79': 'Cross-Site Scripting (XSS)',
            'CWE-22': 'Path Traversal',
            'CWE-798': 'Hard-coded Credentials',
            'CWE-502': 'Insecure Deserialization',
        }
        return cwe_names.get(cwe_id, 'Vulnerability')
    
    def get_severity(self, cwe_id: str) -> str:
        """Severity por CWE"""
        critical = ['CWE-89', 'CWE-78', 'CWE-94']
        high = ['CWE-79', 'CWE-22', 'CWE-502', 'CWE-798', 'CWE-611']
        
        if cwe_id in critical:
            return 'CRITICAL'
        elif cwe_id in high:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def scan_file(self, file_path: Path, chunk_size: int = 60) -> List[Dict]:
        """Scan archivo con chunks grandes"""
        try:
            code = file_path.read_text(encoding='utf-8', errors='ignore')
        except:
            return []
        
        vulnerabilities = []
        lines = code.split('\n')
        
        # Chunks grandes con overlap
        step = chunk_size // 2
        
        for i in range(0, len(lines), step):
            chunk = '\n'.join(lines[i:i+chunk_size])
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
        
        # Deduplicar
        dedup = {}
        for v in vulnerabilities:
            key = (v['file'], v.get('cwe_id', 'VULN'))
            if key not in dedup or v['confidence'] > dedup[key]['confidence']:
                dedup[key] = v
        
        return list(dedup.values())
    
    def scan_directory(self, directory: Path, extensions: List[str]) -> List[Dict]:
        """Scan directorio completo"""
        all_vulns = []
        
        for ext in extensions:
            files = list(directory.rglob(f'*.{ext}'))
            logger.info(f"Scanning {len(files)} .{ext} files...")
            
            for file_path in files:
                vulns = self.scan_file(file_path)
                all_vulns.extend(vulns)
        
        return all_vulns


def generate_html_report(vulnerabilities: List[Dict], output_path: Path):
    """Genera reporte HTML"""
    
    total = len(vulnerabilities)
    by_severity = {
        'CRITICAL': [v for v in vulnerabilities if v.get('severity') == 'CRITICAL'],
        'HIGH': [v for v in vulnerabilities if v.get('severity') == 'HIGH'],
        'MEDIUM': [v for v in vulnerabilities if v.get('severity') == 'MEDIUM'],
    }
    
    by_cwe = {}
    for v in vulnerabilities:
        cwe = v.get('cwe_id', v.get('label', 'Unknown'))
        if cwe not in by_cwe:
            by_cwe[cwe] = []
        by_cwe[cwe].append(v)
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Real-Code ML Vulnerability Scan</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }}
        .badge {{ display: inline-block; padding: 5px 15px; border-radius: 20px; background: #3498db; color: white; margin: 5px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .stat-card .number {{ font-size: 3em; font-weight: bold; }}
        .CRITICAL {{ color: #e74c3c; }}
        .HIGH {{ color: #e67e22; }}
        .MEDIUM {{ color: #f39c12; }}
        .vuln {{ background: white; margin: 15px 0; padding: 25px; border-left: 5px solid; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .vuln.CRITICAL {{ border-color: #e74c3c; }}
        .vuln.HIGH {{ border-color: #e67e22; }}
        .vuln.MEDIUM {{ border-color: #f39c12; }}
        .code {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; font-family: monospace; font-size: 0.9em; }}
        .meta {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 15px 0; }}
        .meta-item {{ padding: 10px; background: #ecf0f1; border-radius: 5px; }}
        h1 {{ margin: 0; font-size: 2.5em; }}
        h2 {{ color: #2c3e50; margin: 30px 0 15px 0; padding-bottom: 10px; border-bottom: 3px solid #3498db; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Real-Code ML Vulnerability Scan</h1>
        <p style="font-size: 1.2em; margin: 10px 0;">Trained with REAL Vulnerable Code</p>
        <p>Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
        <div>
            <span class="badge">Methodology: SEMMA</span>
            <span class="badge">ML: Gradient Boosting</span>
            <span class="badge">Features: 34 AST + Vulnerability Indicators</span>
        </div>
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
    
    <h2>📊 Distribution by CWE</h2>
    <div style="background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
"""
    
    for cwe, vulns in sorted(by_cwe.items(), key=lambda x: len(x[1]), reverse=True):
        percentage = (len(vulns) / total * 100) if total > 0 else 0
        cwe_name = vulns[0].get('type', 'Unknown') if vulns else 'Unknown'
        html += f"""
        <div style="margin: 15px 0;">
            <strong>{cwe}</strong> - {cwe_name}: {len(vulns)} ({percentage:.1f}%)
            <div style="background: #ecf0f1; height: 25px; border-radius: 12px; overflow: hidden; margin-top: 5px;">
                <div style="background: linear-gradient(90deg, #3498db, #2980b9); height: 100%; width: {percentage}%; transition: width 0.3s;"></div>
            </div>
        </div>
"""
    
    html += """
    </div>
    
    <h2>🔍 Detailed Findings</h2>
"""
    
    for i, v in enumerate(vulnerabilities, 1):
        severity = v.get('severity', 'MEDIUM')
        html += f"""
    <div class="vuln {severity}">
        <h3 style="margin: 0 0 15px 0;">{i}. {v.get('type', 'Vulnerability')} <span style="float: right; background: {'#e74c3c' if severity=='CRITICAL' else '#e67e22' if severity=='HIGH' else '#f39c12'}; color: white; padding: 5px 15px; border-radius: 5px; font-size: 0.8em;">{severity}</span></h3>
        <div class="meta">
            <div class="meta-item"><strong>CWE:</strong> {v.get('cwe_id', v.get('label', 'Unknown'))}</div>
            <div class="meta-item"><strong>Confidence:</strong> {v.get('confidence', 0)*100:.1f}%</div>
            <div class="meta-item"><strong>Method:</strong> {v.get('detection_method', 'ML')}</div>
        </div>
        <div class="meta-item" style="margin: 10px 0;"><strong>File:</strong> {v.get('file', 'Unknown')} (lines {v.get('lines', '?')})</div>
        <div class="meta-item" style="margin: 10px 0;"><strong>Path:</strong> <code style="background: #34495e; color: #ecf0f1; padding: 3px 8px; border-radius: 3px;">{v.get('full_path', 'Unknown')}</code></div>
        <details open>
            <summary style="cursor: pointer; font-weight: bold; margin: 15px 0; color: #2c3e50;">📄 Code Snippet</summary>
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
    logger.info("="*60)
    logger.info("SCANNING WITH REAL-CODE TRAINED MODELS")
    logger.info("Minería de Datos + ML (SEMMA)")
    logger.info("="*60)
    
    scanner = RealCodeScanner()
    
    test_dir = Path('/app/test_samples/javaspringvulny-main')
    
    vulnerabilities = scanner.scan_directory(
        test_dir,
        extensions=['java']
    )
    
    logger.info(f"\n✅ Found {len(vulnerabilities)} vulnerabilities")
    
    # Stats
    by_severity = {
        'CRITICAL': [v for v in vulnerabilities if v.get('severity') == 'CRITICAL'],
        'HIGH': [v for v in vulnerabilities if v.get('severity') == 'HIGH'],
        'MEDIUM': [v for v in vulnerabilities if v.get('severity') == 'MEDIUM'],
    }
    
    logger.info(f"Severity:")
    logger.info(f"  CRITICAL: {len(by_severity['CRITICAL'])}")
    logger.info(f"  HIGH: {len(by_severity['HIGH'])}")
    logger.info(f"  MEDIUM: {len(by_severity['MEDIUM'])}")
    
    # Generate report
    output_path = Path('/app/reports/real_code_ml_scan_report.html')
    generate_html_report(vulnerabilities, output_path)
    logger.info(f"\n✅ HTML report: {output_path}")
    
    # JSON
    json_output = {
        'scan_date': datetime.now().isoformat(),
        'methodology': 'SEMMA (Sample, Explore, Modify, Model, Assess)',
        'model_type': 'Gradient Boosting trained on real vulnerable code',
        'total_vulnerabilities': len(vulnerabilities),
        'by_severity': {k: len(v) for k, v in by_severity.items()},
        'vulnerabilities': vulnerabilities
    }
    
    json_path = Path('/app/reports/real_code_ml_scan_results.json')
    json_path.write_text(json.dumps(json_output, indent=2))
    logger.info(f"✅ JSON: {json_path}")


if __name__ == '__main__':
    main()
