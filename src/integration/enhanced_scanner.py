"""
Enhanced CI/CD Vulnerability Scanner with CODE-TRAINED ML Models
Uses models trained specifically on vulnerable code patterns
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, List
from loguru import logger
import numpy as np
import joblib
import re
from datetime import datetime


class EnhancedVulnerabilityScanner:
    """Advanced vulnerability scanner using code-trained ML models"""
    
    def __init__(self, model_name: str = "gradient_boosting", threshold: float = 0.7):
        """
        Initialize scanner with code-trained models
        
        Args:
            model_name: Which model to use (gradient_boosting, random_forest, neural_network, etc.)
            threshold: Detection threshold
        """
        self.model_path = Path("./models")
        self.threshold = threshold
        self.model_name = model_name
        
        self._load_models()
        logger.info(f"Enhanced Scanner initialized with {model_name} (threshold: {threshold})")
    
    def _load_models(self):
        """Load code-trained models"""
        try:
            # Load code-specific model
            model_file = self.model_path / f'{self.model_name}_code_scanner.joblib'
            if model_file.exists():
                self.model = joblib.load(model_file)
                logger.info(f"✅ Loaded code-trained model: {self.model_name}")
            else:
                logger.error(f"Model not found: {model_file}")
                self.model = None
            
            # Load code vectorizer and scaler
            self.vectorizer = joblib.load(self.model_path / 'code_vectorizer.joblib')
            self.scaler = joblib.load(self.model_path / 'code_scaler.joblib')
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            self.model = None
    
    def extract_code_features(self, code: str) -> Dict[str, float]:
        """Extract numerical features from code (must match training)"""
        features = {}
        
        # Length features
        features['code_length'] = len(code)
        features['num_lines'] = code.count('\n') + 1
        features['avg_line_length'] = len(code) / max(features['num_lines'], 1)
        
        # Dangerous patterns
        features['has_sql_keywords'] = int(bool(re.search(r'SELECT|INSERT|UPDATE|DELETE|DROP', code, re.I)))
        features['has_exec_eval'] = int(bool(re.search(r'\bexec\b|\beval\b', code, re.I)))
        features['has_system_call'] = int(bool(re.search(r'system\(|popen\(|shell=True', code, re.I)))
        features['has_file_ops'] = int(bool(re.search(r'open\(|read\(|write\(', code, re.I)))
        features['has_network'] = int(bool(re.search(r'socket\(|request\.|urllib', code, re.I)))
        features['has_crypto'] = int(bool(re.search(r'md5|sha1|hashlib|crypto', code, re.I)))
        features['has_pickle'] = int(bool(re.search(r'pickle|yaml\.load|unserialize', code, re.I)))
        
        # String concatenation (risky)
        features['has_string_concat'] = int(bool(re.search(r'\+\s*["\']|["\']\\s*\+', code)))
        features['has_f_string'] = int(bool(re.search(r'f["\']', code)))
        features['has_format'] = int(bool(re.search(r'\.format\(|%\s*\(', code)))
        
        # Security indicators
        features['has_password'] = int(bool(re.search(r'password|passwd|pwd|secret|key', code, re.I)))
        features['has_hardcoded_string'] = int(bool(re.search(r'=\s*["\'][^"\']{8,}["\']', code)))
        features['has_path_traversal'] = int(bool(re.search(r'\.\./|\.\.\\', code)))
        
        return features
    
    def scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan file with ML model"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not self.model:
                return vulnerabilities
            
            # Split into code chunks (functions, classes, or lines)
            chunks = self._split_code(content)
            
            for chunk_idx, chunk in enumerate(chunks):
                if len(chunk.strip()) < 20:  # Skip trivial chunks
                    continue
                
                # Extract features
                numerical_features = self.extract_code_features(chunk)
                text_features = self.vectorizer.transform([chunk])
                
                # Combine - use numpy arrays to match training format
                X_num = self.scaler.transform(np.array([list(numerical_features.values())]))
                X = np.hstack([X_num, text_features.toarray()])
                
                # Predict
                probability = self.model.predict_proba(X)[0][1]
                
                if probability >= self.threshold:
                    # Find line number
                    line_num = content[:content.find(chunk)].count('\n') + 1 if chunk in content else 0
                    
                    # Identify vulnerability type
                    vuln_type = self._identify_vulnerability_type(chunk, numerical_features)
                    
                    vulnerabilities.append({
                        'file': str(file_path),
                        'line': line_num,
                        'type': vuln_type,
                        'risk_level': 'CRITICAL' if probability >= 0.9 else 'HIGH' if probability >= 0.8 else 'MEDIUM',
                        'description': f'ML detected {vuln_type} (confidence: {probability:.1%})',
                        'code_snippet': chunk[:100] + '...' if len(chunk) > 100 else chunk,
                        'probability': float(probability),
                        'recommendation': self._get_recommendation(vuln_type),
                        'cwe': self._get_cwe(vuln_type),
                        'source': f'ML-{self.model_name}'
                    })
                    
                    logger.info(f"🔴 Detected {vuln_type} in {file_path.name}: {probability:.1%}")
        
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
        
        return vulnerabilities
    
    def _split_code(self, content: str) -> List[str]:
        """Split code into analyzable chunks"""
        # Try to split by functions/methods first
        func_pattern = r'(def\s+\w+\([^)]*\):.*?)(?=\ndef\s|\nclass\s|\Z)'
        functions = re.findall(func_pattern, content, re.DOTALL)
        
        if functions:
            return functions
        
        # Fall back to splitting by significant lines
        lines = content.split('\n')
        chunks = []
        current_chunk = []
        
        for line in lines:
            if line.strip():
                current_chunk.append(line)
                if len(current_chunk) >= 5:  # Chunk every 5 lines
                    chunks.append('\n'.join(current_chunk))
                    current_chunk = []
        
        if current_chunk:
            chunks.append('\n'.join(current_chunk))
        
        return chunks if chunks else [content]
    
    def _identify_vulnerability_type(self, code: str, features: Dict) -> str:
        """Identify specific vulnerability type"""
        if features['has_sql_keywords'] and features['has_string_concat']:
            return 'SQL Injection'
        elif features['has_exec_eval']:
            return 'Command/Code Injection'
        elif features['has_system_call']:
            return 'OS Command Injection'
        elif features['has_pickle']:
            return 'Insecure Deserialization'
        elif features['has_path_traversal']:
            return 'Path Traversal'
        elif features['has_password'] and features['has_hardcoded_string']:
            return 'Hard-coded Secrets'
        elif features['has_crypto'] and re.search(r'md5|sha1', code, re.I):
            return 'Weak Cryptography'
        else:
            return 'Potential Vulnerability'
    
    def _get_cwe(self, vuln_type: str) -> str:
        """Get CWE for vulnerability type"""
        mapping = {
            'SQL Injection': 'CWE-89',
            'Command/Code Injection': 'CWE-78',
            'OS Command Injection': 'CWE-78',
            'Insecure Deserialization': 'CWE-502',
            'Path Traversal': 'CWE-22',
            'Hard-coded Secrets': 'CWE-798',
            'Weak Cryptography': 'CWE-327'
        }
        return mapping.get(vuln_type, 'CWE-Unknown')
    
    def _get_recommendation(self, vuln_type: str) -> str:
        """Get fix recommendation"""
        recommendations = {
            'SQL Injection': 'Use parameterized queries or prepared statements',
            'Command/Code Injection': 'Avoid eval/exec, validate input strictly',
            'OS Command Injection': 'Use subprocess with shell=False and argument lists',
            'Insecure Deserialization': 'Use json.loads() or yaml.safe_load()',
            'Path Traversal': 'Validate paths with os.path.abspath() and check boundaries',
            'Hard-coded Secrets': 'Use environment variables or secret management',
            'Weak Cryptography': 'Use SHA-256 or stronger hashing algorithms'
        }
        return recommendations.get(vuln_type, 'Review code for security issues')
    
    def scan_directory(self, directory: Path) -> List[Dict[str, Any]]:
        """Scan entire directory"""
        all_vulns = []
        extensions = ['.py', '.js', '.java', '.php', '.rb', '.go']
        
        logger.info(f"🔍 Scanning directory: {directory}")
        
        for ext in extensions:
            files = list(directory.rglob(f'*{ext}'))
            logger.info(f"Found {len(files)} {ext} files")
            
            for file_path in files:
                if any(skip in str(file_path) for skip in ['venv', 'node_modules', '__pycache__']):
                    continue
                
                vulns = self.scan_file(file_path)
                all_vulns.extend(vulns)
        
        logger.info(f"✅ Scan complete. Found {len(all_vulns)} vulnerabilities")
        return all_vulns
    
    def generate_report(self, vulnerabilities: List[Dict], output_file: str = None):
        """Generate JSON report"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'model_used': self.model_name,
            'threshold': self.threshold,
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'summary': {
                'by_risk': {},
                'by_type': {}
            }
        }
        
        # Count by risk
        for vuln in vulnerabilities:
            risk = vuln['risk_level']
            report['summary']['by_risk'][risk] = report['summary']['by_risk'].get(risk, 0) + 1
            
            vtype = vuln['type']
            report['summary']['by_type'][vtype] = report['summary']['by_type'].get(vtype, 0) + 1
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"📄 Report saved: {output_file}")
        
        return report


def main():
    parser = argparse.ArgumentParser(description='Enhanced ML Vulnerability Scanner')
    parser.add_argument('--directory', type=str, default='.', help='Directory to scan')
    parser.add_argument('--model', type=str, default='gradient_boosting',
                       choices=['gradient_boosting', 'random_forest', 'neural_network', 'svm', 'decision_tree'],
                       help='ML model to use')
    parser.add_argument('--threshold', type=float, default=0.7, help='Detection threshold')
    parser.add_argument('--output', type=str, help='Output file')
    
    args = parser.parse_args()
    
    scanner = EnhancedVulnerabilityScanner(model_name=args.model, threshold=args.threshold)
    vulnerabilities = scanner.scan_directory(Path(args.directory))
    report = scanner.generate_report(vulnerabilities, args.output)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"🎯 SCAN RESULTS - Model: {args.model}")
    print(f"{'='*60}")
    print(f"Total Vulnerabilities: {len(vulnerabilities)}")
    print(f"\nBy Risk Level:")
    for risk, count in sorted(report['summary']['by_risk'].items()):
        print(f"  {risk}: {count}")
    print(f"\nBy Type:")
    for vtype, count in sorted(report['summary']['by_type'].items()):
        print(f"  {vtype}: {count}")
    
    # Exit with error if critical vulns found
    critical_count = report['summary']['by_risk'].get('CRITICAL', 0)
    if critical_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
