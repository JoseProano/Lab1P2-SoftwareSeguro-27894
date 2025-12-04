#!/usr/bin/env python3
"""
Scanner usando modelo entrenado con DATASET MASIVO
332 samples de múltiples repositorios
94% accuracy, 98% ROC-AUC
"""

import numpy as np
from pathlib import Path
from typing import List, Dict
from loguru import logger
import joblib
from datetime import datetime
import json

# Importar feature extractor
import sys
sys.path.insert(0, '/app/src/models')
from real_data_mining import AdvancedFeatureExtractor

class MassiveMLScanner:
    """
    Scanner usando modelo entrenado con 332 muestras REALES
    Multi-class CWE detection: CWE-22, CWE-79, CWE-798, CWE-89, SAFE
    """
    
    def __init__(self):
        self.models_dir = Path('/app/models')
        self.feature_extractor = AdvancedFeatureExtractor()
        
        logger.info("Loading models trained with MASSIVE dataset...")
        
        self.model = joblib.load(self.models_dir / 'massive_code_vulnerability_detector.joblib')
        self.scaler = joblib.load(self.models_dir / 'massive_code_scaler.joblib')
        self.label_encoder = joblib.load(self.models_dir / 'massive_code_label_encoder.joblib')
        
        # Load metadata
        metadata_path = self.models_dir / 'massive_code_model_metadata.json'
        if metadata_path.exists():
            self.metadata = json.loads(metadata_path.read_text())
            logger.info(f"Model type: {self.metadata.get('model_type')}")
            logger.info(f"Dataset size: {self.metadata.get('dataset_size')} samples")
            logger.info(f"Test accuracy: {self.metadata.get('results', {}).get('neural_network', {}).get('accuracy', 0)*100:.2f}%")
            logger.info(f"Classes: {self.metadata.get('classes')}")
        
        logger.info("✅ Models loaded")
    
    def scan_code(self, code: str, min_confidence: float = 0.5) -> Dict:
        """Scan código usando ML puro"""
        
        # Filtrar código vacío o muy corto
        if len(code.strip()) < 20:
            return {'vulnerable': False, 'reason': 'Too short', 'label': 'SAFE'}
        
        try:
            # Extraer features (34 features AST + vulnerability indicators)
            features = self.feature_extractor.extract_all_features(code)
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            # Predecir
            prediction = self.model.predict(features_scaled)[0]
            proba = self.model.predict_proba(features_scaled)[0]
            
            # Decodificar label
            label = self.label_encoder.inverse_transform([prediction])[0]
            confidence = float(proba[prediction])
            
            # Obtener probabilidades de todas las clases
            class_probabilities = {}
            for i, class_name in enumerate(self.label_encoder.classes_):
                class_probabilities[class_name] = float(proba[i])
            
            if label == 'SAFE':
                return {
                    'vulnerable': False,
                    'label': label,
                    'confidence': confidence,
                    'class_probabilities': class_probabilities
                }
            
            # Es vulnerable
            if confidence < min_confidence:
                return {
                    'vulnerable': False,
                    'label': 'SAFE',
                    'confidence': 1 - confidence,
                    'note': f'Low confidence for {label} ({confidence:.2%})'
                }
            
            return {
                'vulnerable': True,
                'label': label,
                'confidence': confidence,
                'cwe_id': label,
                'type': self.get_cwe_name(label),
                'severity': self.get_severity(label),
                'detection_method': 'ML-Massive-Dataset',
                'class_probabilities': class_probabilities
            }
        
        except Exception as e:
            logger.error(f"Error scanning code: {e}")
            return {'vulnerable': False, 'label': 'ERROR', 'error': str(e)}
    
    def get_cwe_name(self, cwe_id: str) -> str:
        """Mapeo CWE a nombre"""
        cwe_names = {
            'CWE-89': 'SQL Injection',
            'CWE-78': 'OS Command Injection',
            'CWE-79': 'Cross-Site Scripting (XSS)',
            'CWE-22': 'Path Traversal',
            'CWE-798': 'Hard-coded Credentials',
            'CWE-502': 'Insecure Deserialization',
            'CWE-611': 'XML External Entity (XXE)',
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
        
        # Deduplicar por archivo + CWE, mantener mayor confianza
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


def generate_html_report(vulnerabilities: List[Dict], output_path: Path, metadata: Dict):
    """Genera reporte HTML con resultados del modelo masivo"""
    
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
    
    # Obtener métricas del modelo
    model_accuracy = metadata.get('results', {}).get('neural_network', {}).get('accuracy', 0) * 100
    model_f1 = metadata.get('results', {}).get('neural_network', {}).get('f1_score', 0) * 100
    model_roc_auc = metadata.get('results', {}).get('neural_network', {}).get('roc_auc', 0) * 100
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Massive ML Dataset Vulnerability Scan</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; border-radius: 10px; }}
        .badge {{ display: inline-block; padding: 5px 15px; border-radius: 20px; background: #3498db; color: white; margin: 5px; font-size: 0.9em; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .stat-card .number {{ font-size: 3em; font-weight: bold; margin: 10px 0; }}
        .stat-card .label {{ color: #666; font-size: 0.9em; text-transform: uppercase; }}
        .model-metrics {{ background: white; padding: 25px; border-radius: 10px; margin: 20px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 15px; }}
        .metric-item {{ text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .metric-label {{ color: #666; font-size: 0.85em; margin-top: 5px; }}
        .CRITICAL {{ color: #e74c3c; }}
        .HIGH {{ color: #e67e22; }}
        .MEDIUM {{ color: #f39c12; }}
        .vuln {{ background: white; margin: 15px 0; padding: 25px; border-left: 5px solid; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .vuln.CRITICAL {{ border-color: #e74c3c; }}
        .vuln.HIGH {{ border-color: #e67e22; }}
        .vuln.MEDIUM {{ border-color: #f39c12; }}
        .code {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; font-family: 'Consolas', monospace; font-size: 0.9em; }}
        .meta {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 15px 0; }}
        .meta-item {{ padding: 10px; background: #ecf0f1; border-radius: 5px; font-size: 0.9em; }}
        .confidence-bar {{ background: #ecf0f1; height: 25px; border-radius: 12px; overflow: hidden; margin-top: 5px; }}
        .confidence-fill {{ background: linear-gradient(90deg, #3498db, #2980b9); height: 100%; transition: width 0.3s; }}
        h1 {{ margin: 0; font-size: 2.5em; }}
        h2 {{ color: #2c3e50; margin: 30px 0 15px 0; padding-bottom: 10px; border-bottom: 3px solid #3498db; }}
        .proba-table {{ width: 100%; margin-top: 10px; }}
        .proba-table td {{ padding: 5px; }}
        .proba-bar {{ height: 20px; background: #ecf0f1; border-radius: 5px; overflow: hidden; }}
        .proba-fill {{ background: #3498db; height: 100%; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Massive ML Dataset Vulnerability Scan</h1>
        <p style="font-size: 1.2em; margin: 10px 0;">Trained with 332 Real Vulnerable Code Samples</p>
        <p>Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
        <div>
            <span class="badge">Methodology: SEMMA</span>
            <span class="badge">ML: Neural Network (256-128-64-32)</span>
            <span class="badge">Features: 34 AST + Indicators</span>
            <span class="badge">Multi-Class: 5 CWE Types</span>
        </div>
    </div>
    
    <div class="model-metrics">
        <h2 style="margin-top: 0;">📈 Model Performance Metrics</h2>
        <div class="metric-grid">
            <div class="metric-item">
                <div class="metric-value">{model_accuracy:.1f}%</div>
                <div class="metric-label">Test Accuracy</div>
            </div>
            <div class="metric-item">
                <div class="metric-value">{model_f1:.1f}%</div>
                <div class="metric-label">F1-Score</div>
            </div>
            <div class="metric-item">
                <div class="metric-value">{model_roc_auc:.1f}%</div>
                <div class="metric-label">ROC-AUC</div>
            </div>
        </div>
        <p style="margin-top: 15px; color: #666; text-align: center;">
            Trained on: {metadata.get('dataset_size', 0)} samples | 
            Train/Test: {metadata.get('train_size', 0)}/{metadata.get('test_size', 0)} | 
            Classes: {', '.join(metadata.get('classes', []))}
        </p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="number">{total}</div>
            <div class="label">Total Vulnerabilities</div>
        </div>
        <div class="stat-card">
            <div class="number CRITICAL">{len(by_severity['CRITICAL'])}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="number HIGH">{len(by_severity['HIGH'])}</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card">
            <div class="number MEDIUM">{len(by_severity['MEDIUM'])}</div>
            <div class="label">Medium</div>
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
        confidence = v.get('confidence', 0) * 100
        
        # Probabilidades de clases
        class_probs = v.get('class_probabilities', {})
        proba_html = ""
        if class_probs:
            proba_html = "<table class='proba-table'>"
            for cls, prob in sorted(class_probs.items(), key=lambda x: x[1], reverse=True):
                proba_html += f"""
                <tr>
                    <td style="width: 100px;"><strong>{cls}:</strong></td>
                    <td style="width: 60px;">{prob*100:.1f}%</td>
                    <td>
                        <div class="proba-bar">
                            <div class="proba-fill" style="width: {prob*100}%;"></div>
                        </div>
                    </td>
                </tr>
                """
            proba_html += "</table>"
        
        html += f"""
    <div class="vuln {severity}">
        <h3 style="margin: 0 0 15px 0;">{i}. {v.get('type', 'Vulnerability')} <span style="float: right; background: {'#e74c3c' if severity=='CRITICAL' else '#e67e22' if severity=='HIGH' else '#f39c12'}; color: white; padding: 5px 15px; border-radius: 5px; font-size: 0.8em;">{severity}</span></h3>
        <div class="meta">
            <div class="meta-item"><strong>CWE:</strong> {v.get('cwe_id', v.get('label', 'Unknown'))}</div>
            <div class="meta-item"><strong>Method:</strong> {v.get('detection_method', 'ML')}</div>
            <div class="meta-item"><strong>File:</strong> {v.get('file', 'Unknown')}</div>
        </div>
        <div style="margin: 10px 0;">
            <strong>Confidence:</strong> {confidence:.1f}%
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: {confidence}%;"></div>
            </div>
        </div>
        <div class="meta-item" style="margin: 10px 0;"><strong>Lines:</strong> {v.get('lines', '?')}</div>
        <div class="meta-item" style="margin: 10px 0;"><strong>Path:</strong> <code style="background: #34495e; color: #ecf0f1; padding: 3px 8px; border-radius: 3px;">{v.get('full_path', 'Unknown')}</code></div>
        <details open>
            <summary style="cursor: pointer; font-weight: bold; margin: 15px 0; color: #2c3e50;">📄 Code Snippet</summary>
            <div class="code">{v.get('code_snippet', 'N/A')}</div>
        </details>
        <details>
            <summary style="cursor: pointer; font-weight: bold; margin: 15px 0; color: #2c3e50;">📊 Class Probabilities</summary>
            {proba_html}
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
    logger.info("SCANNING WITH MASSIVE DATASET ML MODEL")
    logger.info("332 samples | 94% accuracy | 98% ROC-AUC")
    logger.info("="*60)
    
    scanner = MassiveMLScanner()
    
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
    
    by_cwe = {}
    for v in vulnerabilities:
        cwe = v.get('cwe_id', v.get('label', 'Unknown'))
        if cwe not in by_cwe:
            by_cwe[cwe] = []
        by_cwe[cwe].append(v)
    
    logger.info(f"\nBy Severity:")
    logger.info(f"  CRITICAL: {len(by_severity['CRITICAL'])}")
    logger.info(f"  HIGH: {len(by_severity['HIGH'])}")
    logger.info(f"  MEDIUM: {len(by_severity['MEDIUM'])}")
    
    logger.info(f"\nBy CWE:")
    for cwe, vulns in sorted(by_cwe.items(), key=lambda x: len(x[1]), reverse=True):
        logger.info(f"  {cwe}: {len(vulns)}")
    
    # Generate report
    output_path = Path('/app/reports/massive_ml_scan_report.html')
    generate_html_report(vulnerabilities, output_path, scanner.metadata)
    logger.info(f"\n✅ HTML report: {output_path}")
    
    # JSON
    json_output = {
        'scan_date': datetime.now().isoformat(),
        'methodology': 'SEMMA (Sample, Explore, Modify, Model, Assess)',
        'model_type': 'Neural Network (256-128-64-32)',
        'dataset_size': scanner.metadata.get('dataset_size', 0),
        'model_accuracy': scanner.metadata.get('results', {}).get('neural_network', {}).get('accuracy', 0),
        'model_f1': scanner.metadata.get('results', {}).get('neural_network', {}).get('f1_score', 0),
        'model_roc_auc': scanner.metadata.get('results', {}).get('neural_network', {}).get('roc_auc', 0),
        'total_vulnerabilities': len(vulnerabilities),
        'by_severity': {k: len(v) for k, v in by_severity.items()},
        'by_cwe': {k: len(v) for k, v in by_cwe.items()},
        'vulnerabilities': vulnerabilities
    }
    
    json_path = Path('/app/reports/massive_ml_scan_results.json')
    json_path.write_text(json.dumps(json_output, indent=2))
    logger.info(f"✅ JSON: {json_path}")


if __name__ == '__main__':
    main()
