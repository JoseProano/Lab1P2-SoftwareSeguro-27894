#!/usr/bin/env python3
"""
Advanced Hybrid Scanner - Improved CWE classification
Uses dual-model approach with CWE-specific detection
"""

import joblib
import numpy as np
import re
from pathlib import Path
from loguru import logger
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

class AdvancedHybridScanner:
    def __init__(self, model_path=None, threshold=0.7):
        self.model_path = Path(model_path or '/app/models')
        self.threshold = threshold
        self._load_models()
        
        logger.info(f"🔗 Advanced Hybrid Scanner initialized (threshold: {threshold})")
    
    def _load_models(self):
        """Load advanced models"""
        try:
            # Load vulnerability detector (binary classifier)
            self.vuln_detector = joblib.load(
                self.model_path / 'advanced_vulnerability_detector.joblib'
            )
            logger.info("✅ Loaded advanced vulnerability detector")
            
            # Load CWE classifier (multi-class)
            self.cwe_classifier = joblib.load(
                self.model_path / 'advanced_cwe_classifier.joblib'
            )
            logger.info("✅ Loaded advanced CWE classifier")
            
            # Load feature extractors
            self.vectorizer = joblib.load(
                self.model_path / 'advanced_vectorizer.joblib'
            )
            self.scaler = joblib.load(
                self.model_path / 'advanced_scaler.joblib'
            )
            self.label_encoder = joblib.load(
                self.model_path / 'cwe_label_encoder.joblib'
            )
            logger.info("✅ Loaded feature extractors")
            
        except Exception as e:
            logger.error(f"Error loading advanced models: {e}")
            logger.warning("⚠️ Falling back to basic models...")
            self._load_fallback_models()
    
    def _load_fallback_models(self):
        """Load basic models if advanced not available"""
        try:
            self.vuln_detector = joblib.load(
                self.model_path / 'gradient_boosting_realistic_scanner.joblib'
            )
            self.vectorizer = joblib.load(
                self.model_path / 'realistic_vectorizer.joblib'
            )
            self.scaler = joblib.load(
                self.model_path / 'realistic_scaler.joblib'
            )
            self.cwe_classifier = None
            self.label_encoder = None
            logger.info("✅ Loaded fallback models")
        except Exception as e:
            logger.error(f"Failed to load fallback models: {e}")
            raise
    
    def extract_enhanced_features(self, code):
        """Extract enhanced code features (must match training)"""
        features = []
        
        code_lower = code.lower()
        
        # 1. Code length metrics
        features.append(len(code))
        features.append(len(code.split('\n')))
        features.append(len(code.split()))
        
        # 2. Dangerous function patterns
        dangerous_patterns = {
            'sql': ['select', 'insert', 'update', 'delete', 'drop', 'union', 'exec', 'execute'],
            'exec': ['eval', 'exec', 'system', 'shell', 'runtime', 'subprocess', 'popen'],
            'file': ['open', 'read', 'write', 'file', 'include', 'require', 'load'],
            'crypto': ['md5', 'sha1', 'des', 'rc4'],
            'web': ['request', 'post', 'get', 'cookie', 'session'],
            'secrets': ['password', 'secret', 'key', 'token', 'api_key', 'credential']
        }
        
        for category, patterns in dangerous_patterns.items():
            features.append(sum(1 for p in patterns if p in code_lower))
        
        # 3. Syntax patterns
        features.append(code.count('+'))
        features.append(code.count('"'))
        features.append(code.count("'"))
        features.append(code.count('('))
        features.append(code.count('['))
        features.append(code.count('{'))
        
        # 4. Security anti-patterns
        features.append(1 if ' + ' in code else 0)
        features.append(1 if '.format(' in code else 0)
        features.append(1 if 'f"' in code or "f'" in code else 0)
        features.append(1 if '?' in code else 0)
        features.append(1 if 'prepared' in code_lower else 0)
        features.append(1 if 'escape' in code_lower or 'sanitize' in code_lower else 0)
        
        # 5. Code structure
        features.append(code.count('def ') + code.count('function ') + code.count('public '))
        features.append(code.count('class '))
        features.append(code.count('import ') + code.count('require'))
        
        # 6. Vulnerability indicators
        vuln_indicators = [
            '${', '%s', '%d', '#{',
            '../', '..\\',
            '<script', 'innerHTML', 'document.',
            'pickle.loads', 'unserialize', 'eval(',
        ]
        features.append(sum(1 for indicator in vuln_indicators if indicator in code))
        
        return features
    
    def scan_code_chunk(self, code_chunk, line_number=0):
        """Scan code chunk with advanced CWE classification"""
        try:
            # Extract features
            tfidf_features = self.vectorizer.transform([code_chunk]).toarray()
            numerical_features = np.array([self.extract_enhanced_features(code_chunk)])
            numerical_features = self.scaler.transform(numerical_features)
            
            # Combine features
            X = np.hstack([numerical_features, tfidf_features])
            
            # Step 1: Check if vulnerable
            vuln_proba = self.vuln_detector.predict_proba(X)[0]
            is_vulnerable_proba = vuln_proba[1]  # Probability of being vulnerable
            
            if is_vulnerable_proba < self.threshold:
                return None  # Not vulnerable enough
            
            # Step 2: Classify CWE if vulnerable
            cwe_id = 'CWE-Unknown'
            vulnerability_type = 'Potential Vulnerability'
            
            if self.cwe_classifier is not None:
                cwe_pred = self.cwe_classifier.predict(X)[0]
                cwe_proba = self.cwe_classifier.predict_proba(X)[0]
                cwe_confidence = cwe_proba[cwe_pred]
                
                # Only use CWE classification if confident
                if cwe_confidence > 0.5:
                    cwe_id = self.label_encoder.inverse_transform([cwe_pred])[0]
                    vulnerability_type = self._get_vuln_name(cwe_id)
            
            # Determine severity based on CWE
            severity = self._get_severity(cwe_id)
            
            return {
                'type': vulnerability_type,
                'cwe_id': cwe_id,
                'severity': severity,
                'confidence': float(is_vulnerable_proba),
                'line_number': line_number,
                'code_snippet': code_chunk[:200]
            }
            
        except Exception as e:
            logger.error(f"Error scanning code chunk: {e}")
            return None
    
    def _get_vuln_name(self, cwe_id):
        """Map CWE to vulnerability name"""
        mapping = {
            'CWE-89': 'SQL Injection',
            'CWE-78': 'Command Injection',
            'CWE-79': 'Cross-Site Scripting (XSS)',
            'CWE-22': 'Path Traversal',
            'CWE-798': 'Hard-coded Credentials',
            'CWE-327': 'Weak Cryptography',
            'CWE-502': 'Insecure Deserialization',
            'CWE-352': 'CSRF',
            'CWE-611': 'XXE Injection',
            'CWE-94': 'Code Injection'
        }
        return mapping.get(cwe_id, 'Potential Vulnerability')
    
    def _get_severity(self, cwe_id):
        """Determine severity based on CWE"""
        critical_cwes = ['CWE-89', 'CWE-78', 'CWE-94', 'CWE-502']
        high_cwes = ['CWE-79', 'CWE-22', 'CWE-798', 'CWE-611']
        medium_cwes = ['CWE-327', 'CWE-352']
        
        if cwe_id in critical_cwes:
            return 'CRITICAL'
        elif cwe_id in high_cwes:
            return 'HIGH'
        elif cwe_id in medium_cwes:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def split_code_into_chunks(self, code, language):
        """Split code into analyzable chunks"""
        chunks = []
        lines = code.split('\n')
        
        # Simple chunking by functions/methods
        current_chunk = []
        current_line = 0
        
        for i, line in enumerate(lines):
            # Function/method start patterns
            is_function_start = any(pattern in line for pattern in [
                'def ', 'function ', 'public ', 'private ', 'protected ',
                '@app.', '@GetMapping', '@PostMapping', 'app.get(', 'app.post('
            ])
            
            if is_function_start and current_chunk:
                # Save previous chunk
                chunk_code = '\n'.join(current_chunk)
                if len(chunk_code.strip()) > 10:
                    chunks.append((chunk_code, current_line))
                current_chunk = []
                current_line = i
            
            current_chunk.append(line)
            
            # Also split on class boundaries
            if 'class ' in line and current_chunk and len(current_chunk) > 5:
                chunk_code = '\n'.join(current_chunk[:-1])
                if len(chunk_code.strip()) > 10:
                    chunks.append((chunk_code, current_line))
                current_chunk = [line]
                current_line = i
        
        # Add final chunk
        if current_chunk:
            chunk_code = '\n'.join(current_chunk)
            if len(chunk_code.strip()) > 10:
                chunks.append((chunk_code, current_line))
        
        # If no chunks found, treat whole file as one chunk
        if not chunks:
            chunks = [(code, 0)]
        
        return chunks
    
    def scan_file(self, file_path):
        """Scan a single file"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return []
        
        # Detect language
        language = file_path.suffix.lstrip('.')
        
        # Split into chunks
        chunks = self.split_code_into_chunks(code, language)
        
        vulnerabilities = []
        
        for chunk_code, line_num in chunks:
            result = self.scan_code_chunk(chunk_code, line_num)
            
            if result:
                result['file'] = str(file_path)
                vulnerabilities.append(result)
                
                logger.info(
                    f"🔴 Detected {result['type']} in {file_path.name}: "
                    f"{result['confidence']:.1%} confidence ({result['cwe_id']})"
                )
        
        return vulnerabilities

def main():
    """Test the advanced scanner"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python advanced_hybrid_scanner.py <file_path>")
        sys.exit(1)
    
    scanner = AdvancedHybridScanner(threshold=0.7)
    results = scanner.scan_file(sys.argv[1])
    
    print(f"\n{'='*60}")
    print(f"Vulnerabilities found: {len(results)}")
    print(f"{'='*60}\n")
    
    for i, vuln in enumerate(results, 1):
        print(f"[{i}] {vuln['type']}")
        print(f"    CWE: {vuln['cwe_id']}")
        print(f"    Severity: {vuln['severity']}")
        print(f"    Confidence: {vuln['confidence']:.1%}")
        print(f"    Line: {vuln['line_number']}")
        print()

if __name__ == '__main__':
    main()
