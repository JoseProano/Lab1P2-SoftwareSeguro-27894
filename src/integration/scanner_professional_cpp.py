#!/usr/bin/env python3
"""
Scanner de vulnerabilidades C/C++ usando modelo profesional
Entrenado con 20,000 muestras de DiverseVul + BigVul
"""

import sys
import json
import joblib
import numpy as np
from pathlib import Path
from typing import List, Dict, Tuple
from loguru import logger
from datetime import datetime

sys.path.insert(0, '/app/src/models')
from real_data_mining import AdvancedFeatureExtractor


class ProfessionalCppScanner:
    """
    Scanner usando modelo entrenado con dataset académico profesional
    """
    
    def __init__(self, models_dir: Path = Path('/app/models')):
        self.models_dir = models_dir
        self.feature_extractor = AdvancedFeatureExtractor()
        
        # Cargar modelo entrenado
        logger.info("Loading professional model...")
        self.model = joblib.load(models_dir / 'professional_vulnerability_detector.joblib')
        self.scaler = joblib.load(models_dir / 'professional_scaler.joblib')
        self.label_encoder = joblib.load(models_dir / 'professional_label_encoder.joblib')
        
        # Cargar metadata
        metadata_path = models_dir / 'professional_model_metadata.json'
        self.metadata = json.loads(metadata_path.read_text())
        
        logger.info(f"✅ Model loaded: {self.metadata['model_type']}")
        logger.info(f"   Trained on: {self.metadata['dataset_size']} samples")
        logger.info(f"   Data source: {self.metadata['data_source']}")
        logger.info(f"   Accuracy: {self.metadata['results'][self.metadata['model_type']]['accuracy']:.2%}")
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Escanea un archivo C/C++ buscando vulnerabilidades
        """
        logger.info(f"Scanning: {file_path}")
        
        try:
            code = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return []
        
        # Dividir en funciones/chunks para análisis granular
        chunks = self.split_into_chunks(code)
        
        vulnerabilities = []
        
        for i, chunk in enumerate(chunks):
            if len(chunk.strip()) < 50:  # Skip chunks muy pequeños
                continue
            
            try:
                # Extraer features
                features = self.feature_extractor.extract_all_features(chunk)
                features_scaled = self.scaler.transform([features])
                
                # Predecir
                prediction = self.model.predict(features_scaled)[0]
                proba = self.model.predict_proba(features_scaled)[0]
                
                label = self.label_encoder.inverse_transform([prediction])[0]
                confidence = np.max(proba)
                
                if label == 'VULNERABLE' and confidence > 0.65:  # Threshold más alto
                    # Encontrar líneas del chunk
                    start_line = code[:code.find(chunk)].count('\n') + 1 if chunk in code else i * 50
                    end_line = start_line + chunk.count('\n')
                    
                    # Detectar CWE probable basado en patrones
                    probable_cwes = self.detect_probable_cwe(chunk)
                    
                    # Extraer snippet relevante (evitar headers/comments)
                    snippet = self.extract_relevant_snippet(chunk)
                    
                    vuln = {
                        'file': str(file_path),
                        'chunk_index': i,
                        'lines': f"{start_line}-{end_line}",
                        'confidence': float(confidence),
                        'label': label,
                        'probable_cwes': probable_cwes,
                        'code_snippet': snippet
                    }
                    
                    vulnerabilities.append(vuln)
                    logger.warning(f"  ⚠️  VULNERABLE @ lines {start_line}-{end_line} (confidence: {confidence:.2%})")
                    logger.warning(f"      Probable CWEs: {', '.join(probable_cwes)}")
                
            except Exception as e:
                logger.debug(f"Failed to analyze chunk {i}: {e}")
                continue
        
        return vulnerabilities
    
    def extract_relevant_snippet(self, code: str, max_length: int = 300) -> str:
        """
        Extrae el snippet más relevante del código
        Evita mostrar solo headers/comments
        """
        lines = code.split('\n')
        
        # Saltar comentarios iniciales y headers
        start_idx = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith('//') and not stripped.startswith('/*') and not stripped.startswith('*') and not stripped.startswith('#include'):
                start_idx = i
                break
        
        # Buscar líneas con código interesante (no solo declaraciones)
        interesting_lines = []
        for i, line in enumerate(lines[start_idx:], start_idx):
            stripped = line.strip()
            # Líneas con operaciones, llamadas, asignaciones
            if any(x in stripped for x in ['=', '(', '{', 'malloc', 'free', 'memcpy', 'strcpy', 'printf', 'scanf', 'if', 'for', 'while']):
                interesting_lines.append(i)
        
        # Tomar desde la primera línea interesante
        if interesting_lines:
            start = max(0, interesting_lines[0] - 1)
            snippet_lines = lines[start:min(len(lines), start + 15)]
        else:
            snippet_lines = lines[start_idx:start_idx + 15]
        
        snippet = '\n'.join(snippet_lines)
        
        if len(snippet) > max_length:
            snippet = snippet[:max_length] + '...'
        
        return snippet
    
    def split_into_chunks(self, code: str, chunk_size: int = 50) -> List[str]:
        """
        Divide código en chunks analizables
        Prioriza funciones completas sobre chunks por líneas
        """
        chunks = []
        import re
        
        # Intentar extraer funciones completas (mejor análisis)
        # Patrón: tipo nombre(...) { ... }
        function_pattern = r'(?:void|int|char|float|double|struct|static|extern)\s+\*?\w+\s*\([^)]*\)\s*\{[^}]*\}'
        functions = re.findall(function_pattern, code, re.DOTALL | re.MULTILINE)
        
        if functions and len(functions) > 3:  # Si encontramos suficientes funciones
            return functions
        
        # Fallback: dividir por líneas sin overlap excesivo
        lines = code.split('\n')
        
        # Saltar headers/comments iniciales
        start_line = 0
        for i, line in enumerate(lines[:30]):  # Revisar primeras 30 líneas
            if any(x in line.lower() for x in ['int main', 'void ', 'struct ', '#include']):
                if i > 5:  # Si hay al menos 5 líneas de headers
                    start_line = max(0, i - 2)
                    break
        
        # Chunks con menos overlap
        for i in range(start_line, len(lines), chunk_size):
            chunk = '\n'.join(lines[i:i+chunk_size+20])  # Solo 20 líneas de overlap
            if len(chunk.strip()) > 100:  # Chunks más sustanciales
                chunks.append(chunk)
        
        return chunks
    
    def detect_probable_cwe(self, code: str) -> List[str]:
        """
        Detecta CWEs probables con análisis más preciso
        Solo reporta CWEs con alta probabilidad
        """
        import re
        cwes = []
        code_lower = code.lower()
        
        # Buffer Overflow (CWE-787) - ALTA CONFIANZA
        unsafe_funcs = ['strcpy(', 'strcat(', 'gets(', 'sprintf(']
        if any(func in code_lower for func in unsafe_funcs):
            # Verificar que no haya versiones seguras cerca
            if not any(safe in code_lower for safe in ['strncpy', 'strncat', 'fgets', 'snprintf']):
                cwes.append('CWE-787 (Buffer Overflow)')
        
        # Use After Free (CWE-416) - ALTA CONFIANZA
        if 'free(' in code_lower:
            # Buscar patrones de double-free o use-after-free
            lines = code_lower.split('\n')
            free_count = code_lower.count('free(')
            if free_count > 1:  # Múltiples frees
                cwes.append('CWE-416 (Use After Free / Double Free)')
            elif any('free(' in line and any(x in line for x in ['[', '->', '*']) for line in lines[lines.index(next((l for l in lines if 'free(' in l), ''))+1:]):
                cwes.append('CWE-416 (Use After Free)')
        
        # Integer Overflow (CWE-190) - MEDIA CONFIANZA
        if re.search(r'malloc\s*\([^)]*[+*]', code_lower):
            cwes.append('CWE-190 (Integer Overflow in Allocation)')
        
        # NULL Pointer Dereference (CWE-476) - MEDIA CONFIANZA
        if '->' in code:
            # Buscar dereferencias sin checks previos
            lines = code.split('\n')
            for i, line in enumerate(lines):
                if '->' in line and i > 0:
                    prev_lines = '\n'.join(lines[max(0, i-3):i]).lower()
                    if not any(check in prev_lines for check in ['if', 'null', '==', '!=']):
                        cwes.append('CWE-476 (NULL Pointer Dereference)')
                        break
        
        # Command Injection (CWE-78) - ALTA CONFIANZA
        if any(x in code_lower for x in ['system(', 'popen(', 'execv']):
            cwes.append('CWE-78 (Command Injection)')
        
        # Format String (CWE-134) - MEDIA CONFIANZA
        if re.search(r'printf\s*\([^"]*%[^"]*\)', code):
            # Format string con variable (no literal)
            if not re.search(r'printf\s*\(\s*"', code):
                cwes.append('CWE-134 (Format String Vulnerability)')
        
        # Input Validation (CWE-20) - BAJA CONFIANZA
        if any(x in code_lower for x in ['scanf(', 'gets(', 'fgets(']):
            if not any(check in code_lower for check in ['strlen', 'sizeof', 'validate', 'bounds']):
                cwes.append('CWE-20 (Improper Input Validation)')
        
        return cwes if cwes else ['CWE-Unknown']
    
    def scan_repository(self, repo_path: Path, extensions: List[str] = ['.c', '.cpp', '.cc', '.h']) -> Dict:
        """
        Escanea repositorio completo
        """
        logger.info(f"\n{'='*70}")
        logger.info(f"SCANNING REPOSITORY: {repo_path}")
        logger.info(f"{'='*70}")
        
        # Encontrar archivos C/C++
        files = []
        for ext in extensions:
            files.extend(repo_path.rglob(f'*{ext}'))
        
        logger.info(f"Found {len(files)} C/C++ files")
        
        all_vulnerabilities = []
        scanned_files = 0
        
        for file_path in files:
            vulns = self.scan_file(file_path)
            if vulns:
                all_vulnerabilities.extend(vulns)
                scanned_files += 1
        
        # Generar reporte
        report = self.generate_report(repo_path, files, all_vulnerabilities, scanned_files)
        
        return report
    
    def generate_report(self, repo_path: Path, all_files: List[Path], 
                       vulnerabilities: List[Dict], scanned_files: int) -> Dict:
        """
        Genera reporte completo del escaneo
        """
        # Agrupar por archivo
        by_file = {}
        for vuln in vulnerabilities:
            file = vuln['file']
            if file not in by_file:
                by_file[file] = []
            by_file[file].append(vuln)
        
        # Agrupar por CWE
        by_cwe = {}
        for vuln in vulnerabilities:
            for cwe in vuln['probable_cwes']:
                if cwe not in by_cwe:
                    by_cwe[cwe] = []
                by_cwe[cwe].append(vuln)
        
        report = {
            'scan_date': datetime.now().isoformat(),
            'repository': str(repo_path),
            'model': self.metadata['model_type'],
            'model_accuracy': self.metadata['results'][self.metadata['model_type']]['accuracy'],
            'statistics': {
                'total_files': len(all_files),
                'scanned_files': scanned_files,
                'files_with_vulnerabilities': len(by_file),
                'total_vulnerabilities': len(vulnerabilities),
                'unique_cwes': len(by_cwe)
            },
            'vulnerabilities_by_file': by_file,
            'vulnerabilities_by_cwe': {cwe: len(vulns) for cwe, vulns in by_cwe.items()},
            'all_vulnerabilities': vulnerabilities
        }
        
        # Imprimir resumen
        self.print_report_summary(report)
        
        return report
    
    def generate_html_report(self, report: Dict, output_path: Path):
        """
        Genera reporte HTML visual
        """
        stats = report['statistics']
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {Path(report['repository']).name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 600;
        }}
        
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 12px rgba(0,0,0,0.15);
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .stat-card.danger .stat-number {{
            color: #dc3545;
        }}
        
        .stat-card.warning .stat-number {{
            color: #ffc107;
        }}
        
        .stat-card.success .stat-number {{
            color: #28a745;
        }}
        
        .section {{
            padding: 30px;
        }}
        
        .section-title {{
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #1e3c72;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .cwe-chart {{
            display: grid;
            gap: 15px;
            margin-top: 20px;
        }}
        
        .cwe-bar {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .cwe-label {{
            min-width: 300px;
            font-weight: 500;
            color: #333;
        }}
        
        .cwe-progress {{
            flex: 1;
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            position: relative;
        }}
        
        .cwe-progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #dc3545, #ff6b6b);
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            color: white;
            font-weight: bold;
            transition: width 0.5s ease;
        }}
        
        .vulnerability-card {{
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: box-shadow 0.2s;
        }}
        
        .vulnerability-card:hover {{
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        .vulnerability-header {{
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .vulnerability-header.high {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        
        .vulnerability-header.medium {{
            background: #fff3cd;
            border-left-color: #ffc107;
        }}
        
        .vulnerability-file {{
            font-weight: bold;
            color: #333;
            font-size: 1.1em;
        }}
        
        .vulnerability-badge {{
            background: #dc3545;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
        }}
        
        .vulnerability-details {{
            padding: 20px;
            display: none;
            background: #f8f9fa;
        }}
        
        .vulnerability-details.active {{
            display: block;
        }}
        
        .vuln-item {{
            background: white;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .vuln-meta {{
            display: flex;
            gap: 20px;
            margin-bottom: 10px;
            flex-wrap: wrap;
        }}
        
        .vuln-meta-item {{
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 0.9em;
            color: #666;
        }}
        
        .confidence {{
            font-weight: bold;
            color: #28a745;
        }}
        
        .confidence.high {{
            color: #dc3545;
        }}
        
        .cwes {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }}
        
        .cwe-tag {{
            background: #e7f3ff;
            color: #0066cc;
            padding: 5px 12px;
            border-radius: 5px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        
        .code-snippet {{
            background: #282c34;
            color: #abb2bf;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.5;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #dee2e6;
        }}
        
        .toggle-icon {{
            transition: transform 0.3s;
        }}
        
        .toggle-icon.active {{
            transform: rotate(180deg);
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            .vulnerability-details {{
                display: block !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Vulnerability Scan Report</h1>
            <div class="subtitle">{Path(report['repository']).name}</div>
            <div class="subtitle" style="margin-top: 10px; font-size: 0.9em;">
                Scan Date: {report['scan_date'].split('T')[0]} {report['scan_date'].split('T')[1].split('.')[0]}
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Files Scanned</div>
                <div class="stat-number">{stats['scanned_files']}</div>
                <div style="color: #999; font-size: 0.85em;">of {stats['total_files']} total</div>
            </div>
            
            <div class="stat-card danger">
                <div class="stat-label">Vulnerabilities</div>
                <div class="stat-number">{stats['total_vulnerabilities']}</div>
                <div style="color: #999; font-size: 0.85em;">detected</div>
            </div>
            
            <div class="stat-card warning">
                <div class="stat-label">Vulnerable Files</div>
                <div class="stat-number">{stats['files_with_vulnerabilities']}</div>
                <div style="color: #999; font-size: 0.85em;">affected</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">CWE Types</div>
                <div class="stat-number">{stats['unique_cwes']}</div>
                <div style="color: #999; font-size: 0.85em;">unique</div>
            </div>
            
            <div class="stat-card success">
                <div class="stat-label">Model Accuracy</div>
                <div class="stat-number">{report['model_accuracy']*100:.1f}%</div>
                <div style="color: #999; font-size: 0.85em;">{report['model']}</div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">📊 Vulnerabilities by CWE Type</h2>
            <div class="cwe-chart">
"""
        
        # CWE chart
        max_count = max(report['vulnerabilities_by_cwe'].values()) if report['vulnerabilities_by_cwe'] else 1
        for cwe, count in sorted(report['vulnerabilities_by_cwe'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / max_count) * 100
            html += f"""
                <div class="cwe-bar">
                    <div class="cwe-label">{cwe}</div>
                    <div class="cwe-progress">
                        <div class="cwe-progress-fill" style="width: {percentage}%">{count}</div>
                    </div>
                </div>
"""
        
        html += """
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">🔍 Detected Vulnerabilities by File</h2>
"""
        
        # Vulnerabilities by file
        for file_path, vulns in sorted(report['vulnerabilities_by_file'].items(), key=lambda x: len(x[1]), reverse=True):
            file_name = Path(file_path).name
            severity = 'high' if len(vulns) > 2 else 'medium'
            
            html += f"""
            <div class="vulnerability-card">
                <div class="vulnerability-header {severity}" onclick="toggleDetails(this)">
                    <div class="vulnerability-file">📄 {file_name}</div>
                    <div style="display: flex; gap: 15px; align-items: center;">
                        <div class="vulnerability-badge">{len(vulns)} vulnerabilities</div>
                        <span class="toggle-icon">▼</span>
                    </div>
                </div>
                <div class="vulnerability-details">
"""
            
            for i, vuln in enumerate(vulns, 1):
                confidence_class = 'high' if vuln['confidence'] > 0.75 else ''
                html += f"""
                    <div class="vuln-item">
                        <div style="font-weight: bold; margin-bottom: 10px;">Vulnerability #{i} - Lines {vuln['lines']}</div>
                        <div class="vuln-meta">
                            <div class="vuln-meta-item">
                                <span>🎯 Confidence:</span>
                                <span class="confidence {confidence_class}">{vuln['confidence']*100:.2f}%</span>
                            </div>
                            <div class="vuln-meta-item">
                                <span>📊 Chunk:</span>
                                <span>{vuln['chunk_index']}</span>
                            </div>
                        </div>
                        <div class="cwes">
"""
                
                for cwe in vuln['probable_cwes']:
                    html += f'<span class="cwe-tag">{cwe}</span>\n'
                
                html += f"""
                        </div>
                        <div class="code-snippet">{vuln['code_snippet'].replace('<', '&lt;').replace('>', '&gt;')}</div>
                    </div>
"""
            
            html += """
                </div>
            </div>
"""
        
        html += f"""
        </div>
        
        <div class="footer">
            <p><strong>Professional C/C++ Vulnerability Scanner</strong></p>
            <p>Powered by Neural Network ML Model trained on DiverseVul + BigVul datasets</p>
            <p>Dataset: 20,000 samples | Model: {report['model']} | Accuracy: {report['model_accuracy']*100:.2f}%</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Generated on {report['scan_date']}</p>
        </div>
    </div>
    
    <script>
        function toggleDetails(header) {{
            const details = header.nextElementSibling;
            const icon = header.querySelector('.toggle-icon');
            
            details.classList.toggle('active');
            icon.classList.toggle('active');
        }}
    </script>
</body>
</html>
"""
        
        output_path.write_text(html, encoding='utf-8')
        logger.info(f"✅ HTML report saved to: {output_path}")
    
    def print_report_summary(self, report: Dict):
        """
        Imprime resumen del reporte en consola
        """
        stats = report['statistics']
        
        logger.info(f"\n{'='*70}")
        logger.info(f"SCAN RESULTS - {report['scan_date']}")
        logger.info(f"{'='*70}")
        logger.info(f"Repository: {report['repository']}")
        logger.info(f"Model: {report['model']} (accuracy: {report['model_accuracy']:.2%})")
        logger.info(f"\nStatistics:")
        logger.info(f"  Total files found: {stats['total_files']}")
        logger.info(f"  Files scanned: {stats['scanned_files']}")
        logger.info(f"  Files with vulnerabilities: {stats['files_with_vulnerabilities']}")
        logger.info(f"  Total vulnerabilities: {stats['total_vulnerabilities']}")
        logger.info(f"  Unique CWE types: {stats['unique_cwes']}")
        
        logger.info(f"\nVulnerabilities by CWE:")
        for cwe, count in sorted(report['vulnerabilities_by_cwe'].items(), 
                                key=lambda x: x[1], reverse=True):
            logger.info(f"  {cwe}: {count}")
        
        logger.info(f"\nTop vulnerable files:")
        by_file = report['vulnerabilities_by_file']
        for file, vulns in sorted(by_file.items(), 
                                 key=lambda x: len(x[1]), reverse=True)[:10]:
            logger.info(f"  {Path(file).name}: {len(vulns)} vulnerabilities")
        
        logger.info(f"{'='*70}\n")


def main():
    """
    Main entry point
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Professional C/C++ Vulnerability Scanner')
    parser.add_argument('repo_path', type=str, help='Path to repository to scan')
    parser.add_argument('--output', type=str, help='Output JSON report file', default=None)
    
    args = parser.parse_args()
    
    repo_path = Path(args.repo_path)
    
    if not repo_path.exists():
        logger.error(f"Repository not found: {repo_path}")
        return 1
    
    # Escanear
    scanner = ProfessionalCppScanner()
    report = scanner.scan_repository(repo_path)
    
    # Guardar reportes (JSON + HTML)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    reports_dir = Path('/app/reports')
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    if args.output:
        output_path = Path(args.output)
        json_path = output_path
        html_path = output_path.with_suffix('.html')
    else:
        # Default output
        json_path = reports_dir / f"scan_{timestamp}.json"
        html_path = reports_dir / f"scan_{timestamp}.html"
    
    # Guardar JSON
    json_path.write_text(json.dumps(report, indent=2))
    logger.info(f"✅ JSON report saved to: {json_path}")
    
    # Guardar HTML
    scanner.generate_html_report(report, html_path)
    
    return 0


if __name__ == '__main__':
    exit(main())
