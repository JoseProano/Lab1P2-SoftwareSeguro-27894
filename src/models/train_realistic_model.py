"""
Train realistic vulnerability detection model
"""
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from loguru import logger
import re


def extract_features(code):
    """Extract numerical features from code"""
    return {
        'code_length': len(code),
        'num_lines': code.count('\n') + 1,
        'avg_line_length': len(code) / max(code.count('\n') + 1, 1),
        'has_sql_keywords': int(bool(re.search(r'SELECT|INSERT|UPDATE|DELETE|DROP', code, re.I))),
        'has_exec_eval': int(bool(re.search(r'\bexec\b|\beval\b', code, re.I))),
        'has_system_call': int(bool(re.search(r'system\(|popen\(|shell=True', code, re.I))),
        'has_file_ops': int(bool(re.search(r'open\(|read\(|write\(', code, re.I))),
        'has_network': int(bool(re.search(r'socket\(|request\.|urllib', code, re.I))),
        'has_crypto': int(bool(re.search(r'md5|sha1|hashlib|crypto', code, re.I))),
        'has_pickle': int(bool(re.search(r'pickle|yaml\.load|unserialize', code, re.I))),
        'has_string_concat': int(bool(re.search(r'\+\s*["\']|["\']\s*\+', code))),
        'has_f_string': int(bool(re.search(r'f["\']', code))),
        'has_format': int(bool(re.search(r'\.format\(|%\s*\(', code))),
        'has_password': int(bool(re.search(r'password|passwd|pwd|secret|key', code, re.I))),
        'has_hardcoded_string': int(bool(re.search(r'=\s*["\'][^"\']{8,}["\']', code))),
        'has_path_traversal': int(bool(re.search(r'\.\.|/etc/|/var/', code)))
    }


def train_realistic_model():
    """Train model with realistic data"""
    
    # Load dataset
    logger.info("📚 Loading realistic training data...")
    with open('/app/data/realistic_training_data.json') as f:
        data = json.load(f)
    
    logger.info(f"Loaded {len(data)} samples")
    
    # Prepare data
    X_codes = [s['code'] for s in data]
    y = np.array([s['vulnerable'] for s in data])
    
    logger.info("🔧 Extracting features...")
    numerical_features = pd.DataFrame([extract_features(code) for code in X_codes])
    
    # TF-IDF vectorizer (character-level for code patterns)
    logger.info("📝 Vectorizing code...")
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 3), max_features=5000)
    X_text = vectorizer.fit_transform(X_codes)
    
    # Scale numerical features
    scaler = StandardScaler()
    X_num = scaler.fit_transform(numerical_features.values)
    
    # Combine features
    X = np.hstack([X_num, X_text.toarray()])
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    
    logger.info(f"Training samples: {len(X_train)}, Test samples: {len(X_test)}")
    
    # Train model
    logger.info("🎯 Training Gradient Boosting model...")
    model = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.1,
        random_state=42
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    train_acc = model.score(X_train, y_train)
    test_acc = model.score(X_test, y_test)
    
    logger.info(f"✅ Training Accuracy: {train_acc*100:.1f}%")
    logger.info(f"✅ Test Accuracy: {test_acc*100:.1f}%")
    
    # Save models
    logger.info("💾 Saving models...")
    joblib.dump(model, '/app/models/gradient_boosting_realistic_scanner.joblib')
    joblib.dump(vectorizer, '/app/models/realistic_vectorizer.joblib')
    joblib.dump(scaler, '/app/models/realistic_scaler.joblib')
    
    logger.info("🎉 Realistic model trained successfully!")
    
    return model, vectorizer, scaler


if __name__ == "__main__":
    train_realistic_model()
