"""
HTML Report Generator for Vulnerability Scans
Converts JSON scan results to formatted HTML reports
"""
import json
from datetime import datetime
from pathlib import Path


class HTMLReportGenerator:
    """Generate HTML reports from vulnerability scan results"""
    
    def __init__(self):
        self.template = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Análisis de Vulnerabilidades</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid;
        }
        
        .stat-card.total { border-color: #3498db; }
        .stat-card.critical { border-color: #e74c3c; }
        .stat-card.high { border-color: #e67e22; }
        .stat-card.medium { border-color: #f39c12; }
        
        .stat-card h3 {
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .stat-card .number {
            font-size: 3em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .vulnerabilities {
            padding: 30px;
        }
        
        .vuln-item {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            transition: transform 0.2s;
        }
        
        .vuln-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .vuln-type {
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .severity {
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
        }
        
        .severity.CRITICAL {
            background: #e74c3c;
            color: white;
        }
        
        .severity.HIGH {
            background: #e67e22;
            color: white;
        }
        
        .severity.MEDIUM {
            background: #f39c12;
            color: white;
        }
        
        .severity.LOW {
            background: #95a5a6;
            color: white;
        }
        
        .confidence {
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 6px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            margin-top: 10px;
        }
        
        .vuln-details {
            margin-top: 15px;
        }
        
        .detail-row {
            display: grid;
            grid-template-columns: 150px 1fr;
            padding: 10px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .detail-row:last-child {
            border-bottom: none;
        }
        
        .detail-label {
            font-weight: bold;
            color: #7f8c8d;
        }
        
        .detail-value {
            color: #2c3e50;
        }
        
        .code-snippet {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin-top: 10px;
        }
        
        .recommendation {
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin-top: 15px;
            border-radius: 4px;
        }
        
        .recommendation h4 {
            color: #2e7d32;
            margin-bottom: 8px;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }
        
        .model-info {
            background: #ecf0f1;
            padding: 20px;
            margin: 20px 30px;
            border-radius: 8px;
        }
        
        .model-info h3 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Reporte de Análisis de Vulnerabilidades</h1>
            <p>Análisis realizado con Machine Learning</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Generado: {timestamp}</p>
        </div>
        
        <div class="summary">
            <div class="stat-card total">
                <h3>Total Vulnerabilidades</h3>
                <div class="number">{total_vulns}</div>
            </div>
            <div class="stat-card critical">
                <h3>Críticas</h3>
                <div class="number">{critical_count}</div>
            </div>
            <div class="stat-card high">
                <h3>Altas</h3>
                <div class="number">{high_count}</div>
            </div>
            <div class="stat-card medium">
                <h3>Medias</h3>
                <div class="number">{medium_count}</div>
            </div>
        </div>
        
        <div class="model-info">
            <h3>⚙️ Información del Modelo</h3>
            <p><strong>Modelo:</strong> {model_name}</p>
            <p><strong>Umbral de Confianza:</strong> {threshold}%</p>
            <p><strong>Archivos Analizados:</strong> {files_scanned}</p>
        </div>
        
        <div class="vulnerabilities">
            <h2 style="margin-bottom: 20px; color: #2c3e50;">📋 Vulnerabilidades Detectadas</h2>
            {vulnerability_items}
        </div>
        
        <div class="footer">
            <p>Reporte generado por el Sistema de Detección de Vulnerabilidades ML</p>
            <p>Lab 1 - Desarrollo de Software Seguro</p>
        </div>
    </div>
</body>
</html>
"""
    
    def generate_vulnerability_item(self, vuln):
        """Generate HTML for a single vulnerability"""
        code_snippet = vuln.get('code_snippet', 'N/A')
        if code_snippet and code_snippet != 'N/A':
            code_html = f'<div class="code-snippet">{self._escape_html(code_snippet)}</div>'
        else:
            code_html = ''
        
        recommendation = vuln.get('recommendation', 'Revisar el código y aplicar las mejores prácticas de seguridad.')
        
        # Handle both old and new field names
        vuln_type = vuln.get('vulnerability_type', vuln.get('type', 'Unknown'))
        severity = vuln.get('severity', vuln.get('risk_level', 'UNKNOWN'))
        confidence = vuln.get('confidence', vuln.get('probability', 0) * 100)
        
        return f"""
            <div class="vuln-item">
                <div class="vuln-header">
                    <div class="vuln-type">🔴 {vuln_type}</div>
                    <span class="severity {severity}">{severity}</span>
                </div>
                
                <div class="confidence">
                    Confianza: {confidence:.1f}%
                </div>
                
                <div class="vuln-details">
                    <div class="detail-row">
                        <div class="detail-label">Archivo:</div>
                        <div class="detail-value">{vuln['file']}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Línea:</div>
                        <div class="detail-value">{vuln['line']}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">CWE:</div>
                        <div class="detail-value">{vuln.get('cwe', 'N/A')}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Descripción:</div>
                        <div class="detail-value">{vuln.get('description', 'Vulnerabilidad detectada por el modelo ML')}</div>
                    </div>
                </div>
                
                {code_html}
                
                <div class="recommendation">
                    <h4>💡 Recomendación</h4>
                    <p>{recommendation}</p>
                </div>
            </div>
        """
    
    def _escape_html(self, text):
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#039;'))
    
    def generate_report(self, json_file, output_file):
        """Generate HTML report from JSON scan results"""
        # Load JSON data
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Extract total vulnerabilities
        total_vulns = data.get('total_vulnerabilities', 0)
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in data.get('vulnerabilities', []):
            risk = vuln.get('risk_level', 'UNKNOWN')
            severity_counts[risk] = severity_counts.get(risk, 0) + 1
        
        # Count by severity
        critical_count = severity_counts.get('CRITICAL', 0)
        high_count = severity_counts.get('HIGH', 0)
        medium_count = severity_counts.get('MEDIUM', 0)
        
        # Generate vulnerability items
        vuln_items_html = ''
        for vuln in data.get('vulnerabilities', []):
            vuln_items_html += self.generate_vulnerability_item(vuln)
        
        # Fill template
        html_content = self.template.format(
            timestamp=datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            total_vulns=total_vulns,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            model_name=data.get('model_used', 'N/A'),
            threshold=int(data.get('threshold', 0.7) * 100),
            files_scanned=len(set(v['file'] for v in data.get('vulnerabilities', []))),
            vulnerability_items=vuln_items_html if vuln_items_html else '<p>No se detectaron vulnerabilidades.</p>'
        )
        
        # Save HTML file
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ HTML report generated: {output_file}")
        return output_file


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python html_report_generator.py <json_file> <output_html>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    output_file = sys.argv[2]
    
    generator = HTMLReportGenerator()
    generator.generate_report(json_file, output_file)
