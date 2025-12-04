#!/usr/bin/env python3
"""
Best-of-Both-Worlds Scanner
Combines realistic model (high recall) + advanced model (precise CWE classification)
"""

import joblib
import numpy as np
from pathlib import Path
from loguru import logger

class ImprovedHybridScanner:
    def __init__(self, threshold=0.7):
        self.model_path = Path('/app/models')
        self.threshold = threshold
        self._load_all_models()
        logger.info(f"🔗 Improved Hybrid Scanner initialized (threshold: {threshold})")
    
    def _load_all_models(self):
        """Load both realistic and advanced models"""
        try:
            # Load REALISTIC model (high recall - catches more)
            self.realistic_detector = joblib.load(
                self.model_path / 'gradient_boosting_realistic_scanner.joblib'
            )
            self.realistic_vectorizer = joblib.load(
                self.model_path / 'realistic_vectorizer.joblib'
            )
            self.realistic_scaler = joblib.load(
                self.model_path / 'realistic_scaler.joblib'
            )
            logger.info("✅ Loaded realistic model (high recall)")
            
            # Load ADVANCED models (precise CWE classification)
            try:
                self.advanced_detector = joblib.load(
                    self.model_path / 'advanced_vulnerability_detector.joblib'
                )
                self.advanced_vectorizer = joblib.load(
                    self.model_path / 'advanced_vectorizer.joblib'
                )
                self.advanced_scaler = joblib.load(
                    self.model_path / 'advanced_scaler.joblib'
                )
                self.cwe_classifier = joblib.load(
                    self.model_path / 'advanced_cwe_classifier.joblib'
                )
                self.label_encoder = joblib.load(
                    self.model_path / 'cwe_label_encoder.joblib'
                )
                logger.info("✅ Loaded advanced models (CWE classification)")
                self.has_advanced = True
            except:
                logger.warning("⚠️ Advanced models not available, using realistic only")
                self.has_advanced = False
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            raise
    
    def extract_realistic_features(self, code):
        """Extract features for realistic model"""
        features = []
        code_lower = code.lower()
        
        # Basic metrics
        features.append(len(code))
        features.append(len(code.split('\n')))
        features.append(len(code.split()))
        
        # Dangerous patterns
        dangerous_keywords = ['eval', 'exec', 'system', 'sql', 'query', 'select',
                            'insert', 'update', 'delete', 'password', 'secret',
                            'md5', 'sha1', 'pickle']
        features.append(sum(1 for kw in dangerous_keywords if kw in code_lower))
        
        # Syntax patterns
        features.append(code.count('+'))
        features.append(code.count('"'))
        features.append(code.count("'"))
        features.append(code.count('('))
        features.append(code.count('['))
        
        # Security indicators
        features.append(1 if ' + ' in code else 0)
        features.append(1 if '.format(' in code else 0)
        features.append(1 if '?' in code else 0)
        features.append(1 if '../' in code or '..\\'  in code else 0)
        
        return features
    
    def extract_advanced_features(self, code):
        """Extract features for advanced model"""
        features = []
        code_lower = code.lower()
        
        # Extended metrics
        features.append(len(code))
        features.append(len(code.split('\n')))
        features.append(len(code.split()))
        
        # Categorized dangerous patterns
        patterns = {
            'sql': ['select', 'insert', 'update', 'delete', 'drop', 'union', 'exec'],
            'exec': ['eval', 'exec', 'system', 'shell', 'runtime', 'subprocess'],
            'file': ['open', 'read', 'write', 'file', 'include', 'load'],
            'crypto': ['md5', 'sha1', 'des', 'rc4'],
            'web': ['request', 'post', 'get', 'cookie'],
            'secrets': ['password', 'secret', 'key', 'token', 'api_key']
        }
        
        for category, keywords in patterns.items():
            features.append(sum(1 for kw in keywords if kw in code_lower))
        
        # Syntax
        for char in ['+', '"', "'", '(', '[', '{']:
            features.append(code.count(char))
        
        # Anti-patterns
        features.append(1 if ' + ' in code else 0)
        features.append(1 if '.format(' in code else 0)
        features.append(1 if 'f"' in code or "f'" in code else 0)
        features.append(1 if '?' in code else 0)
        features.append(1 if 'prepared' in code_lower else 0)
        features.append(1 if 'escape' in code_lower or 'sanitize' in code_lower else 0)
        
        # Structure
        features.append(code.count('def ') + code.count('function ') + code.count('public '))
        features.append(code.count('class '))
        features.append(code.count('import ') + code.count('require'))
        
        # Vuln indicators
        indicators = ['${', '%s', '../', '<script', 'innerHTML', 'pickle.loads', 'unserialize']
        features.append(sum(1 for ind in indicators if ind in code))
        
        return features
    
    def scan_code_chunk(self, code_chunk, line_number=0):
        """Scan code using both models"""
        try:
            # Step 1: Check with REALISTIC model (high recall)
            tfidf_real = self.realistic_vectorizer.transform([code_chunk]).toarray()
            num_real = np.array([self.extract_realistic_features(code_chunk)])
            num_real = self.realistic_scaler.transform(num_real)
            X_real = np.hstack([num_real, tfidf_real])
            
            realistic_proba = self.realistic_detector.predict_proba(X_real)[0][1]
            
            if realistic_proba < self.threshold:
                return None  # Not vulnerable according to realistic model
            
            # Step 2: If vulnerable, try to classify with ADVANCED model
            cwe_id = 'CWE-Unknown'
            vulnerability_type = 'Potential Vulnerability'
            final_confidence = realistic_proba
            
            if self.has_advanced:
                try:
                    # Extract features for advanced model
                    tfidf_adv = self.advanced_vectorizer.transform([code_chunk]).toarray()
                    num_adv = np.array([self.extract_advanced_features(code_chunk)])
                    num_adv = self.advanced_scaler.transform(num_adv)
                    X_adv = np.hstack([num_adv, tfidf_adv])
                    
                    # Classify CWE
                    cwe_pred = self.cwe_classifier.predict(X_adv)[0]
                    cwe_proba = self.cwe_classifier.predict_proba(X_adv)[0]
                    cwe_confidence = cwe_proba[cwe_pred]
                    
                    # Use CWE classification if confident enough
                    if cwe_confidence > 0.4:  # Lower threshold for CWE
                        cwe_id = self.label_encoder.inverse_transform([cwe_pred])[0]
                        vulnerability_type = self._get_vuln_name(cwe_id)
                        # Combine confidences
                        final_confidence = (realistic_proba + cwe_confidence) / 2
                
                except Exception as e:
                    logger.debug(f"CWE classification failed: {e}")
            
            # Determine severity
            severity = self._get_severity(cwe_id)
            
            return {
                'type': vulnerability_type,
                'cwe_id': cwe_id,
                'severity': severity,
                'confidence': float(final_confidence),
                'line_number': line_number,
                'code_snippet': code_chunk[:200]
            }
            
        except Exception as e:
            logger.error(f"Error scanning chunk: {e}")
            return None
    
    def _get_vuln_name(self, cwe_id):
        """Map CWE to name"""
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
        """Determine severity"""
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
        """Split code into chunks"""
        chunks = []
        lines = code.split('\n')
        
        current_chunk = []
        current_line = 0
        
        for i, line in enumerate(lines):
            is_function_start = any(p in line for p in [
                'def ', 'function ', 'public ', 'private ', 'protected ',
                '@app.', '@GetMapping', '@PostMapping', 'app.get(', 'app.post('
            ])
            
            if is_function_start and current_chunk:
                chunk_code = '\n'.join(current_chunk)
                if len(chunk_code.strip()) > 10:
                    chunks.append((chunk_code, current_line))
                current_chunk = []
                current_line = i
            
            current_chunk.append(line)
        
        if current_chunk:
            chunk_code = '\n'.join(current_chunk)
            if len(chunk_code.strip()) > 10:
                chunks.append((chunk_code, current_line))
        
        if not chunks:
            chunks = [(code, 0)]
        
        return chunks
    
    def scan_file(self, file_path):
        """Scan file"""
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
        
        language = file_path.suffix.lstrip('.')
        chunks = self.split_code_into_chunks(code, language)
        
        vulnerabilities = []
        
        for chunk_code, line_num in chunks:
            result = self.scan_code_chunk(chunk_code, line_num)
            
            if result:
                result['file'] = str(file_path)
                vulnerabilities.append(result)
                
                logger.info(
                    f"🔴 Detected {result['type']} in {file_path.name}: "
                    f"{result['confidence']:.1%} ({result['cwe_id']})"
                )
        
        return vulnerabilities

# Test
if __name__ == '__main__':
    scanner = ImprovedHybridScanner(threshold=0.7)
    results = scanner.scan_file('/app/test_samples/javaspringvulny-main/src/main/java/hawk/service/SearchService.java')
    
    print(f"\n{'='*60}")
    print(f"Vulnerabilities: {len(results)}")
    print(f"{'='*60}\n")
    
    for r in results:
        print(f"{r['type']} ({r['cwe_id']})")
        print(f"  Confidence: {r['confidence']:.1%}")
        print(f"  Severity: {r['severity']}")
        print()
