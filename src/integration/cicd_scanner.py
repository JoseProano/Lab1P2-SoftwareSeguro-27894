"""
CI/CD Integration Scanner
Scans code for vulnerabilities and integrates with CI/CD pipelines
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, List
from loguru import logger
import numpy as np
import joblib
import ast
import re
from datetime import datetime


class CICDVulnerabilityScanner:
    """Vulnerability scanner for CI/CD integration"""
    
    def __init__(self, model_path: str = "./models", threshold: float = 0.7):
        """
        Initialize scanner
        
        Args:
            model_path: Path to trained models
            threshold: Probability threshold for vulnerability detection
        """
        self.model_path = Path(model_path)
        self.threshold = threshold
        
        self.model = None
        self.scaler = None
        self.vectorizer = None
        
        self._load_models()
        
        logger.info(f"CI/CD Scanner initialized (threshold: {threshold})")
    
    def _load_models(self):
        """Load trained models and preprocessors"""
        try:
            # Load best model (typically Random Forest)
            model_file = self.model_path / 'random_forest_classifier.joblib'
            if model_file.exists():
                self.model = joblib.load(model_file)
                logger.info("Model loaded successfully")
            else:
                logger.warning(f"Model not found at {model_file}")
            
            # Load preprocessors
            scaler_file = self.model_path / 'scaler.joblib'
            if scaler_file.exists():
                self.scaler = joblib.load(scaler_file)
            
            vectorizer_file = self.model_path / 'tfidf_vectorizer.joblib'
            if vectorizer_file.exists():
                self.vectorizer = joblib.load(vectorizer_file)
                
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
    
    def scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Scan a single file for vulnerabilities
        
        Args:
            file_path: Path to file
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract code features
            features = self._extract_code_features(content, file_path)
            
            # Check for known vulnerability patterns
            pattern_vulns = self._check_vulnerability_patterns(content, file_path)
            vulnerabilities.extend(pattern_vulns)
            
            # ML-based detection
            if self.model and features:
                ml_vulns = self._ml_predict_vulnerabilities(content, file_path, features)
                vulnerabilities.extend(ml_vulns)
            
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {str(e)}")
        
        return vulnerabilities
    
    def _extract_code_features(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Extract features from code"""
        features = {
            'file_path': str(file_path),
            'lines_of_code': len(content.split('\n')),
            'file_size': len(content),
            'language': file_path.suffix
        }
        
        # Count security-relevant patterns
        features['has_sql'] = int('SELECT' in content.upper() or 'INSERT' in content.upper())
        features['has_exec'] = int('exec(' in content.lower() or 'eval(' in content.lower())
        features['has_shell'] = int('subprocess' in content or 'os.system' in content)
        features['has_network'] = int('requests' in content or 'urllib' in content or 'socket' in content)
        features['has_crypto'] = int('hashlib' in content or 'crypto' in content.lower())
        
        return features
    
    def _check_vulnerability_patterns(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Check for known vulnerability patterns"""
        vulnerabilities = []
        
        # Define vulnerability patterns
        patterns = {
            'SQL Injection': [
                (r'execute\s*\(\s*["\']SELECT.*?\+', 'String concatenation in SQL query'),
                (r'\.format\s*\(.*?SELECT', 'String formatting in SQL query'),
                (r'f["\']SELECT.*?\{', 'F-string in SQL query')
            ],
            'Command Injection': [
                (r'os\.system\s*\([^)]*\+', 'String concatenation in system command'),
                (r'subprocess\.(call|run|Popen)\([^)]*\+', 'Unsafe subprocess usage'),
                (r'eval\s*\(', 'Use of eval() - potential code injection')
            ],
            'Path Traversal': [
                (r'open\s*\([^)]*\+', 'Unsafe file path concatenation'),
                (r'\.\./', 'Potential path traversal pattern')
            ],
            'Hard-coded Secrets': [
                (r'password\s*=\s*["\'][^"\']+["\']', 'Hard-coded password'),
                (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hard-coded API key'),
                (r'secret\s*=\s*["\'][^"\']+["\']', 'Hard-coded secret')
            ],
            'Insecure Deserialization': [
                (r'pickle\.loads?\(', 'Unsafe pickle usage'),
                (r'yaml\.load\(', 'Unsafe YAML load')
            ],
            'Weak Cryptography': [
                (r'md5\(', 'Use of MD5 (weak hash)'),
                (r'sha1\(', 'Use of SHA1 (weak hash)')
            ]
        }
        
        lines = content.split('\n')
        
        for vuln_type, pattern_list in patterns.items():
            for pattern, description in pattern_list:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append({
                            'file': str(file_path),
                            'line': line_num,
                            'type': vuln_type,
                            'description': description,
                            'code_snippet': line.strip(),
                            'risk_level': self._classify_risk(vuln_type),
                            'probability': 0.85,  # High confidence for pattern matching
                            'cwe': self._get_cwe_for_type(vuln_type),
                            'recommendation': self._get_recommendation(vuln_type)
                        })
        
        return vulnerabilities
    
    def _ml_predict_vulnerabilities(
        self,
        content: str,
        file_path: Path,
        features: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Use ML model to predict vulnerabilities"""
        vulnerabilities = []
        
        try:
            if not self.vectorizer or not self.model:
                return vulnerabilities
                
            # Create features matching the training pipeline (53 numerical + 5000 TF-IDF = 5053 total)
            # Text vectorization
            text_features = self.vectorizer.transform([content])
            
            # Create 53 numerical features matching feature_engineering.py
            numerical_features = np.array([[
                # Basic metrics (3)
                features.get('lines_of_code', 0),
                features.get('cyclomatic_complexity', 0),
                features.get('maintainability_index', 50),
                
                # Text features (4)
                len(content), len(content.split()),
                len([w for w in content.split() if len(w) > 5]),
                content.count('critical') + content.count('severe'),
                
                # Temporal features (7)
                2025, 12, 4, 1, 0, 0, 0,
                
                # CVSS features (4)
                features.get('maintainability_index', 50) / 10,
                1 if features.get('maintainability_index', 50) < 20 else 0,
                1 if features.get('maintainability_index', 50) < 40 else 0,
                1 if features.get('maintainability_index', 50) < 70 else 0,
                
                # CWE features (10)
                1 if 'SELECT' in content.upper() else 0,
                1 if 'os.system' in content else 0,
                1 if 'pickle' in content else 0,
                1 if '../' in content else 0,
                1 if 'password' in content.lower() else 0,
                1 if 'exec' in content else 0,
                1 if 'import' in content else 0,
                1 if 'md5' in content else 0,
                1 if 'assert' in content else 0,
                features.get('has_sql', 0),
                
                # Severity encoding (5)
                0, 0,
                1 if features.get('cyclomatic_complexity', 0) > 10 else 0,
                1 if features.get('cyclomatic_complexity', 0) <= 5 else 0,
                0,
                
                # Pattern detection (7)
                features.get('has_sql', 0),
                features.get('has_exec', 0),
                features.get('has_shell', 0),
                features.get('has_network', 0),
                features.get('has_file_ops', 0),
                features.get('has_crypto', 0),
                features.get('has_random', 0),
                
                # Code quality (5)
                features.get('num_functions', 0),
                features.get('num_classes', 0),
                features.get('num_imports', 0),
                features.get('num_comments', 0),
                features.get('comment_ratio', 0),
                
                # Halstead metrics (8)
                features.get('halstead_difficulty', 0),
                features.get('halstead_effort', 0),
                features.get('halstead_bugs', 0),
                features.get('halstead_time', 0),
                features.get('halstead_volume', 0),
                0, 0, 0  # Padding to reach 53
            ]])
            
            # Combine: numerical (53) + text (5000) = 5053 features
            # BUT: scaler was trained ONLY on the 53 numerical features
            # So we scale numerical first, THEN concatenate with text
            
            if self.scaler:
                numerical_features = self.scaler.transform(numerical_features)
            
            X = np.hstack([numerical_features, text_features.toarray()])
            
            # Predict
            probability = self.model.predict_proba(X)[0][1]
            
            # Log prediction for debugging
            logger.info(f"ML prediction for {file_path.name}: {probability:.3f}")
            
            if probability >= self.threshold:
                vulnerabilities.append({
                    'file': str(file_path),
                    'line': 0,
                    'type': 'ML Detected Vulnerability',
                    'risk_level': 'CRITICAL' if probability >= 0.95 else 'HIGH' if probability >= 0.85 else 'MEDIUM',
                    'description': f'ML model detected vulnerability (confidence: {probability:.1%})',
                    'probability': float(probability),
                    'recommendation': 'Review this file for security issues',
                    'cwe': 'CWE-Unknown',
                    'source': 'ML'
                })
        
        except Exception as e:
            logger.error(f"ML prediction error: {str(e)}")
        
        return vulnerabilities
    
    def _classify_risk(self, vuln_type: str) -> str:
        """Classify risk level based on vulnerability type"""
        critical_types = ['SQL Injection', 'Command Injection', 'Insecure Deserialization']
        high_types = ['Path Traversal', 'Hard-coded Secrets']
        
        if vuln_type in critical_types:
            return 'CRITICAL'
        elif vuln_type in high_types:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _get_cwe_for_type(self, vuln_type: str) -> str:
        """Get CWE identifier for vulnerability type"""
        cwe_mapping = {
            'SQL Injection': 'CWE-89',
            'Command Injection': 'CWE-78',
            'Path Traversal': 'CWE-22',
            'Hard-coded Secrets': 'CWE-798',
            'Insecure Deserialization': 'CWE-502',
            'Weak Cryptography': 'CWE-327'
        }
        return cwe_mapping.get(vuln_type, 'CWE-Unknown')
    
    def _get_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for fixing vulnerability"""
        recommendations = {
            'SQL Injection': 'Use parameterized queries or ORM instead of string concatenation',
            'Command Injection': 'Use subprocess with array arguments, avoid shell=True',
            'Path Traversal': 'Validate and sanitize file paths, use os.path.join()',
            'Hard-coded Secrets': 'Use environment variables or secret management services',
            'Insecure Deserialization': 'Use safe alternatives like json.loads() or yaml.safe_load()',
            'Weak Cryptography': 'Use SHA-256 or stronger hashing algorithms'
        }
        return recommendations.get(vuln_type, 'Review code and apply security best practices')
    
    def scan_directory(self, directory: Path, extensions: List[str] = None) -> List[Dict[str, Any]]:
        """
        Scan directory for vulnerabilities
        
        Args:
            directory: Directory to scan
            extensions: File extensions to scan (default: .py, .js, .java, .txt)
            
        Returns:
            List of all detected vulnerabilities
        """
        if extensions is None:
            extensions = ['.py', '.js', '.java', '.php', '.rb', '.go', '.txt', '.md']
        
        all_vulnerabilities = []
        
        logger.info(f"Scanning directory: {directory}")
        
        for ext in extensions:
            files = list(directory.rglob(f'*{ext}'))
            logger.info(f"Found {len(files)} {ext} files")
            
            for file_path in files:
                # Skip virtual environments and dependencies
                if any(skip in str(file_path) for skip in ['venv', 'node_modules', '__pycache__', '.git']):
                    continue
                
                vulns = self.scan_file(file_path)
                all_vulnerabilities.extend(vulns)
        
        logger.info(f"Scan complete. Found {len(all_vulnerabilities)} potential vulnerabilities")
        return all_vulnerabilities
    
    def generate_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        output_format: str = 'json',
        output_file: str = None
    ) -> str:
        """
        Generate vulnerability report
        
        Args:
            vulnerabilities: List of vulnerabilities
            output_format: Format (json, html, markdown)
            output_file: Output file path
            
        Returns:
            Report content
        """
        report_data = {
            'scan_date': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'summary': self._generate_summary(vulnerabilities)
        }
        
        # Always generate HTML report for easy viewing
        html_report = self._generate_html_report(report_data)
        html_file = output_file.replace('.json', '.html') if output_file else 'reports/vulnerability_scan_report.html'
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        logger.info(f"HTML report saved to {html_file}")
        
        # Generate requested format
        if output_format == 'json':
            report = json.dumps(report_data, indent=2)
        elif output_format == 'html':
            report = html_report
        elif output_format == 'markdown':
            report = self._generate_markdown_report(report_data)
        else:
            report = json.dumps(report_data, indent=2)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Report saved to {output_file}")
        
        return report
    
    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate vulnerability summary"""
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        type_counts = {}
        
        for vuln in vulnerabilities:
            risk = vuln.get('risk_level', 'UNKNOWN')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            
            vuln_type = vuln.get('type', 'Unknown')
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        return {
            'by_risk_level': risk_counts,
            'by_type': type_counts
        }
    
    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        vulns = report_data['vulnerabilities']
        summary = report_data['summary']
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; }}
                h1 {{ color: #e74c3c; }}
                .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0; }}
                .summary-card {{ padding: 15px; border-radius: 5px; text-align: center; }}
                .critical {{ background: #e74c3c; color: white; }}
                .high {{ background: #e67e22; color: white; }}
                .medium {{ background: #f39c12; color: white; }}
                .low {{ background: #27ae60; color: white; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #34495e; color: white; }}
                .vulnerability {{ margin: 20px 0; padding: 15px; border-left: 4px solid #e74c3c; background: #fff5f5; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 Vulnerability Scan Report</h1>
                <p><strong>Scan Date:</strong> {report_data['scan_date']}</p>
                <p><strong>Total Vulnerabilities:</strong> {report_data['total_vulnerabilities']}</p>
                
                <div class="summary">
                    <div class="summary-card critical">
                        <h2>{summary['by_risk_level']['CRITICAL']}</h2>
                        <p>Critical</p>
                    </div>
                    <div class="summary-card high">
                        <h2>{summary['by_risk_level']['HIGH']}</h2>
                        <p>High</p>
                    </div>
                    <div class="summary-card medium">
                        <h2>{summary['by_risk_level']['MEDIUM']}</h2>
                        <p>Medium</p>
                    </div>
                    <div class="summary-card low">
                        <h2>{summary['by_risk_level']['LOW']}</h2>
                        <p>Low</p>
                    </div>
                </div>
                
                <h2>Detected Vulnerabilities</h2>
        """
        
        for vuln in vulns:
            html += f"""
                <div class="vulnerability">
                    <h3>{vuln['type']} - {vuln['risk_level']}</h3>
                    <p><strong>File:</strong> {vuln['file']} (Line {vuln['line']})</p>
                    <p><strong>Description:</strong> {vuln['description']}</p>
                    <p><strong>CWE:</strong> {vuln.get('cwe', 'N/A')}</p>
                    <p><strong>Recommendation:</strong> {vuln['recommendation']}</p>
                    {f"<p><code>{vuln.get('code_snippet', '')}</code></p>" if vuln.get('code_snippet') else ''}
                </div>
            """
        
        html += """
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_markdown_report(self, report_data: Dict[str, Any]) -> str:
        """Generate Markdown report"""
        vulns = report_data['vulnerabilities']
        summary = report_data['summary']
        
        md = f"""# 🔒 Vulnerability Scan Report

**Scan Date:** {report_data['scan_date']}  
**Total Vulnerabilities:** {report_data['total_vulnerabilities']}

## Summary

| Risk Level | Count |
|------------|-------|
| 🔴 Critical | {summary['by_risk_level']['CRITICAL']} |
| 🟠 High | {summary['by_risk_level']['HIGH']} |
| 🟡 Medium | {summary['by_risk_level']['MEDIUM']} |
| 🟢 Low | {summary['by_risk_level']['LOW']} |

## Detected Vulnerabilities

"""
        
        for i, vuln in enumerate(vulns, 1):
            md += f"""
### {i}. {vuln['type']} ({vuln['risk_level']})

- **File:** `{vuln['file']}` (Line {vuln['line']})
- **Description:** {vuln['description']}
- **CWE:** {vuln.get('cwe', 'N/A')}
- **Recommendation:** {vuln['recommendation']}

"""
            if vuln.get('code_snippet'):
                md += f"```\n{vuln['code_snippet']}\n```\n\n"
        
        return md


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='CI/CD Vulnerability Scanner')
    parser.add_argument('--mode', choices=['ci', 'scan', 'report'], default='scan',
                       help='Operation mode')
    parser.add_argument('--directory', type=str, default='.',
                       help='Directory to scan')
    parser.add_argument('--threshold', type=float, default=0.7,
                       help='Vulnerability detection threshold')
    parser.add_argument('--output-format', choices=['json', 'html', 'markdown'], default='json',
                       help='Output format')
    parser.add_argument('--output-file', type=str,
                       help='Output file path')
    parser.add_argument('--input-file', type=str,
                       help='Input file for report mode')
    
    args = parser.parse_args()
    
    scanner = CICDVulnerabilityScanner(threshold=args.threshold)
    
    if args.mode in ['ci', 'scan']:
        # Scan directory
        vulnerabilities = scanner.scan_directory(Path(args.directory))
        
        # Generate report
        scanner.generate_report(
            vulnerabilities,
            output_format=args.output_format,
            output_file=args.output_file
        )
        
        # Exit with error code if critical vulnerabilities found
        critical_count = sum(1 for v in vulnerabilities if v['risk_level'] == 'CRITICAL')
        if critical_count > 0:
            logger.error(f"Found {critical_count} critical vulnerabilities")
            sys.exit(1)
    
    elif args.mode == 'report':
        # Generate report from existing scan data
        if args.input_file:
            with open(args.input_file, 'r') as f:
                data = json.load(f)
            vulnerabilities = data.get('vulnerabilities', [])
            
            scanner.generate_report(
                vulnerabilities,
                output_format=args.output_format,
                output_file=args.output_file
            )


if __name__ == "__main__":
    main()
