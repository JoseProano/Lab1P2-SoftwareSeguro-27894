#!/usr/bin/env python3
"""
Advanced Model Training - Improved CWE classification and accuracy
Uses 2000+ samples with better feature engineering
"""

import json
import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from collections import Counter

class AdvancedModelTrainer:
    def __init__(self):
        self.data_dir = Path('/app/data')
        self.model_dir = Path('/app/models')
        self.model_dir.mkdir(exist_ok=True)
        
        # Enhanced feature extraction
        self.vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(2, 5),  # Extended n-grams
            max_features=10000,  # More features
            min_df=2,
            max_df=0.9
        )
        
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
    
    def load_training_data(self):
        """Load advanced training data"""
        data_file = self.data_dir / 'advanced_training_data.json'
        
        print(f"📥 Loading training data from {data_file}...")
        
        with open(data_file) as f:
            samples = json.load(f)
        
        print(f"✅ Loaded {len(samples)} samples")
        
        # Print distribution
        vuln_count = sum(1 for s in samples if s['vulnerable'] == 1)
        safe_count = len(samples) - vuln_count
        print(f"   Vulnerable: {vuln_count}")
        print(f"   Safe: {safe_count}")
        
        # CWE distribution
        cwe_dist = Counter(s['cwe_id'] for s in samples)
        print(f"\n📊 CWE Distribution:")
        for cwe, count in sorted(cwe_dist.items()):
            print(f"   {cwe}: {count}")
        
        return samples
    
    def extract_enhanced_features(self, code):
        """Extract enhanced code features"""
        features = []
        
        code_lower = code.lower()
        
        # 1. Code length metrics
        features.append(len(code))
        features.append(len(code.split('\n')))
        features.append(len(code.split()))
        
        # 2. Dangerous function patterns (expanded)
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
        features.append(code.count('+'))  # String concatenation
        features.append(code.count('"'))  # Quote usage
        features.append(code.count("'"))  # Single quotes
        features.append(code.count('('))  # Function calls
        features.append(code.count('['))  # Array access
        features.append(code.count('{'))  # Block/object usage
        
        # 4. Security anti-patterns
        features.append(1 if ' + ' in code else 0)  # Concatenation
        features.append(1 if '.format(' in code else 0)  # String formatting
        features.append(1 if 'f"' in code or "f'" in code else 0)  # f-strings
        features.append(1 if '?' in code else 0)  # Parameterized queries
        features.append(1 if 'prepared' in code_lower else 0)  # PreparedStatement
        features.append(1 if 'escape' in code_lower or 'sanitize' in code_lower else 0)
        
        # 5. Code structure
        features.append(code.count('def ') + code.count('function ') + code.count('public '))
        features.append(code.count('class '))
        features.append(code.count('import ') + code.count('require'))
        
        # 6. Vulnerability indicators
        vuln_indicators = [
            '${', '%s', '%d', '#{',  # String interpolation
            '../', '..\\',  # Path traversal
            '<script', 'innerHTML', 'document.',  # XSS
            'pickle.loads', 'unserialize', 'eval(',  # Dangerous functions
        ]
        features.append(sum(1 for indicator in vuln_indicators if indicator in code))
        
        return features
    
    def prepare_training_data(self, samples):
        """Prepare features and labels"""
        print("\n🔧 Extracting features...")
        
        codes = [s['code'] for s in samples]
        labels = [s['vulnerable'] for s in samples]
        cwe_labels = [s['cwe_id'] for s in samples]
        
        # TF-IDF features
        print("   Vectorizing code with TF-IDF...")
        tfidf_features = self.vectorizer.fit_transform(codes).toarray()
        
        # Numerical features
        print("   Extracting numerical features...")
        numerical_features = np.array([
            self.extract_enhanced_features(code) for code in codes
        ])
        
        # Scale numerical features
        numerical_features = self.scaler.fit_transform(numerical_features)
        
        # Combine features
        X = np.hstack([numerical_features, tfidf_features])
        y = np.array(labels)
        
        print(f"✅ Feature extraction complete")
        print(f"   Feature dimensions: {X.shape}")
        print(f"   Samples: {len(y)}")
        
        return X, y, cwe_labels
    
    def train_vulnerability_detector(self, X, y):
        """Train binary classifier (vulnerable vs safe)"""
        print("\n🤖 Training Vulnerability Detector...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"   Training samples: {len(X_train)}")
        print(f"   Test samples: {len(X_test)}")
        
        # Train Gradient Boosting
        model = GradientBoostingClassifier(
            n_estimators=300,  # More trees
            max_depth=7,  # Deeper trees
            learning_rate=0.05,  # Lower learning rate
            min_samples_split=10,
            min_samples_leaf=5,
            subsample=0.8,
            random_state=42,
            verbose=1
        )
        
        print("\n   Training model...")
        model.fit(X_train, y_train)
        
        # Evaluate
        train_acc = model.score(X_train, y_train)
        test_acc = model.score(X_test, y_test)
        
        print(f"\n   Training Accuracy: {train_acc:.1%}")
        print(f"   Test Accuracy: {test_acc:.1%}")
        
        # Cross-validation
        cv_scores = cross_val_score(model, X_train, y_train, cv=5)
        print(f"   Cross-Validation Accuracy: {cv_scores.mean():.1%} (+/- {cv_scores.std() * 2:.1%})")
        
        # Detailed metrics
        y_pred = model.predict(X_test)
        print(f"\n📊 Classification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=['Safe', 'Vulnerable'],
                                   digits=3))
        
        return model, X_test, y_test
    
    def train_cwe_classifier(self, X, cwe_labels, samples):
        """Train multi-class CWE classifier"""
        print("\n🔬 Training CWE Classifier...")
        
        # Filter only vulnerable samples
        vuln_indices = [i for i, s in enumerate(samples) if s['vulnerable'] == 1]
        X_vuln = X[vuln_indices]
        cwe_vuln = [cwe_labels[i] for i in vuln_indices]
        
        print(f"   Vulnerable samples: {len(X_vuln)}")
        
        # Encode CWE labels
        y_cwe = self.label_encoder.fit_transform(cwe_vuln)
        
        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            X_vuln, y_cwe, test_size=0.2, random_state=42, stratify=y_cwe
        )
        
        # Train Random Forest for CWE classification
        cwe_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            verbose=1
        )
        
        print("\n   Training CWE classifier...")
        cwe_model.fit(X_train, y_train)
        
        # Evaluate
        train_acc = cwe_model.score(X_train, y_train)
        test_acc = cwe_model.score(X_test, y_test)
        
        print(f"\n   Training Accuracy: {train_acc:.1%}")
        print(f"   Test Accuracy: {test_acc:.1%}")
        
        # Detailed report
        y_pred = cwe_model.predict(X_test)
        cwe_names = self.label_encoder.classes_
        print(f"\n📊 CWE Classification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=cwe_names,
                                   digits=3))
        
        return cwe_model
    
    def save_models(self, vuln_model, cwe_model):
        """Save all models and encoders"""
        print("\n💾 Saving models...")
        
        # Save vulnerability detector
        joblib.dump(vuln_model, self.model_dir / 'advanced_vulnerability_detector.joblib')
        print("   ✅ Vulnerability detector saved")
        
        # Save CWE classifier
        joblib.dump(cwe_model, self.model_dir / 'advanced_cwe_classifier.joblib')
        print("   ✅ CWE classifier saved")
        
        # Save vectorizer and scaler
        joblib.dump(self.vectorizer, self.model_dir / 'advanced_vectorizer.joblib')
        joblib.dump(self.scaler, self.model_dir / 'advanced_scaler.joblib')
        print("   ✅ Vectorizer and scaler saved")
        
        # Save label encoder
        joblib.dump(self.label_encoder, self.model_dir / 'cwe_label_encoder.joblib')
        print("   ✅ Label encoder saved")
        
        print(f"\n📁 Models saved to: {self.model_dir}")

def main():
    print("🚀 Advanced Model Training")
    print("=" * 60)
    
    trainer = AdvancedModelTrainer()
    
    # Load data
    samples = trainer.load_training_data()
    
    # Prepare features
    X, y, cwe_labels = trainer.prepare_training_data(samples)
    
    # Train vulnerability detector (binary)
    vuln_model, X_test, y_test = trainer.train_vulnerability_detector(X, y)
    
    # Train CWE classifier (multi-class)
    cwe_model = trainer.train_cwe_classifier(X, cwe_labels, samples)
    
    # Save models
    trainer.save_models(vuln_model, cwe_model)
    
    print("\n✅ Advanced model training complete!")
    print("\n📊 Summary:")
    print(f"   Training samples: {len(samples)}")
    print(f"   Feature dimensions: {X.shape[1]}")
    print(f"   Vulnerability classes: 2 (Safe/Vulnerable)")
    print(f"   CWE classes: {len(set(cwe_labels)) - 1}")  # Exclude 'SAFE'

if __name__ == '__main__':
    main()
