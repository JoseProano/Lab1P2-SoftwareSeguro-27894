"""Generate HTML report from JSON vulnerability scan"""
import json
import sys
from pathlib import Path
from datetime import datetime


def escape_html(text):
    """Escape HTML special characters"""
    return (str(text)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#039;'))


def generate_html_report(json_path, output_path):
    """Generate HTML report from JSON scan results"""
    
    # Load JSON data
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Extract statistics
    total_vulns = data.get('total_vulnerabilities', 0)
    vulnerabilities = data.get('vulnerabilities', [])
    
    # Count by severity
    severity_counts = {}
    for vuln in vulnerabilities:
        risk = vuln.get('risk_level', 'UNKNOWN')
        severity_counts[risk] = severity_counts.get(risk, 0) + 1
    
    critical = severity_counts.get('CRITICAL', 0)
    high = severity_counts.get('HIGH', 0)
    medium = severity_counts.get('MEDIUM', 0)
    low = severity_counts.get('LOW', 0)
    
    # Start HTML
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Vulnerabilidades - ML Scanner</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ font-size: 1.1em; opacity: 0.9; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid;
        }}
        .stat-card.total {{ border-color: #3498db; }}
        .stat-card.critical {{ border-color: #e74c3c; }}
        .stat-card.high {{ border-color: #e67e22; }}
        .stat-card.medium {{ border-color: #f39c12; }}
        .stat-card h3 {{
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        .stat-card .number {{
            font-size: 3em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .model-info {{
            background: #ecf0f1;
            padding: 20px;
            margin: 20px 30px;
            border-radius: 8px;
        }}
        .model-info h3 {{ color: #2c3e50; margin-bottom: 10px; }}
        .vulnerabilities {{ padding: 30px; }}
        .vuln-item {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            transition: transform 0.2s;
        }}
        .vuln-item:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }}
        .vuln-type {{
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .severity {{
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        .severity.CRITICAL {{ background: #e74c3c; color: white; }}
        .severity.HIGH {{ background: #e67e22; color: white; }}
        .severity.MEDIUM {{ background: #f39c12; color: white; }}
        .severity.LOW {{ background: #95a5a6; color: white; }}
        .confidence {{
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 6px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            margin-top: 10px;
        }}
        .vuln-details {{ margin-top: 15px; }}
        .detail-row {{
            display: grid;
            grid-template-columns: 150px 1fr;
            padding: 10px 0;
            border-bottom: 1px solid #f0f0f0;
        }}
        .detail-row:last-child {{ border-bottom: none; }}
        .detail-label {{ font-weight: bold; color: #7f8c8d; }}
        .detail-value {{ color: #2c3e50; }}
        .code-snippet {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin-top: 10px;
            white-space: pre-wrap;
        }}
        .recommendation {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin-top: 15px;
            border-radius: 4px;
        }}
        .recommendation h4 {{ color: #2e7d32; margin-bottom: 8px; }}
        .footer {{
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Reporte de Análisis de Vulnerabilidades</h1>
            <p>Análisis realizado con Machine Learning</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Generado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="stat-card total">
                <h3>Total Vulnerabilidades</h3>
                <div class="number">{total_vulns}</div>
            </div>
            <div class="stat-card critical">
                <h3>Críticas</h3>
                <div class="number">{critical}</div>
            </div>
            <div class="stat-card high">
                <h3>Altas</h3>
                <div class="number">{high}</div>
            </div>
            <div class="stat-card medium">
                <h3>Medias</h3>
                <div class="number">{medium}</div>
            </div>
        </div>
        
        <div class="model-info">
            <h3>⚙️ Información del Modelo</h3>
            <p><strong>Modelo:</strong> {data.get('model_used', 'N/A')}</p>
            <p><strong>Umbral de Confianza:</strong> {int(data.get('threshold', 0.7) * 100)}%</p>
            <p><strong>Archivos Analizados:</strong> {len(set(v['file'] for v in vulnerabilities))}</p>
            <p><strong>Fecha de Escaneo:</strong> {data.get('scan_date', 'N/A')}</p>
        </div>
        
        <div class="vulnerabilities">
            <h2 style="margin-bottom: 20px; color: #2c3e50;">📋 Vulnerabilidades Detectadas</h2>
"""
    
    # Add vulnerability items
    for vuln in vulnerabilities:
        vuln_type = vuln.get('type', 'Unknown')
        severity = vuln.get('risk_level', 'UNKNOWN')
        confidence = vuln.get('probability', 0) * 100
        file_path = vuln.get('file', 'N/A')
        line = vuln.get('line', 0)
        description = vuln.get('description', 'Vulnerabilidad detectada por ML')
        code_snippet = vuln.get('code_snippet', '')
        recommendation = vuln.get('recommendation', 'Revisar el código y aplicar mejores prácticas de seguridad.')
        cwe = vuln.get('cwe', 'N/A')
        
        html += f"""
            <div class="vuln-item">
                <div class="vuln-header">
                    <div class="vuln-type">🔴 {escape_html(vuln_type)}</div>
                    <span class="severity {severity}">{severity}</span>
                </div>
                
                <div class="confidence">
                    Confianza: {confidence:.1f}%
                </div>
                
                <div class="vuln-details">
                    <div class="detail-row">
                        <div class="detail-label">Archivo:</div>
                        <div class="detail-value">{escape_html(file_path)}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Línea:</div>
                        <div class="detail-value">{line}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">CWE:</div>
                        <div class="detail-value">{cwe}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Descripción:</div>
                        <div class="detail-value">{escape_html(description)}</div>
                    </div>
                </div>
"""
        
        if code_snippet:
            html += f"""
                <div class="code-snippet">{escape_html(code_snippet[:500])}</div>
"""
        
        html += f"""
                <div class="recommendation">
                    <h4>💡 Recomendación</h4>
                    <p>{escape_html(recommendation)}</p>
                </div>
            </div>
"""
    
    # Close HTML
    html += """
        </div>
        
        <div class="footer">
            <p>Reporte generado por el Sistema de Detección de Vulnerabilidades ML</p>
            <p>Lab 1 - Desarrollo de Software Seguro - ESPE</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Save HTML file
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"✅ HTML report generated: {output_path}")
    print(f"   Total vulnerabilities: {total_vulns}")
    print(f"   CRITICAL: {critical}, HIGH: {high}, MEDIUM: {medium}, LOW: {low}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python generate_html_report.py <json_file> <output_html>")
        sys.exit(1)
    
    generate_html_report(sys.argv[1], sys.argv[2])
