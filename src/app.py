#!/usr/bin/env python3
"""
Production API - Vulnerability Detection Service
Exposes ML model via REST API for deployment on Render
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
from pathlib import Path
import joblib
import numpy as np
import re
from datetime import datetime

# Add models directory to path
sys.path.insert(0, str(Path(__file__).parent))

app = Flask(__name__)
CORS(app)

# Global model variables
MODEL = None
SCALER = None
LABEL_ENCODER = None

def load_model():
    """Load the trained model on startup"""
    global MODEL, SCALER, LABEL_ENCODER
    
    try:
        models_dir = Path(__file__).parent.parent / 'models'
        MODEL = joblib.load(models_dir / 'cicd_vulnerability_detector.joblib')
        SCALER = joblib.load(models_dir / 'cicd_scaler.joblib')
        LABEL_ENCODER = joblib.load(models_dir / 'cicd_label_encoder.joblib')
        print("✓ Model loaded successfully")
        return True
    except Exception as e:
        print(f"✗ Error loading model: {e}")
        return False

def extract_features(code: str) -> np.ndarray:
    """Extract 34 features from code (same as cicd_analyzer.py)"""
    features = []
    
    # 1-4: Basic code metrics
    lines = code.split('\n')
    features.append(len(lines))
    features.append(len(code))
    features.append(code.count('{'))
    features.append(code.count(';'))
    
    # 5-14: Dangerous function patterns
    dangerous_patterns = [
        r'\bstrcpy\s*\(',
        r'\bgets\s*\(',
        r'\bsprintf\s*\(',
        r'\bstrcat\s*\(',
        r'\bsystem\s*\(',
        r'\bexec[vl]?\s*\(',
        r'\bpopen\s*\(',
        r'\bscanf\s*\(',
        r'\bmalloc\s*\(',
        r'\bfree\s*\(',
    ]
    
    for pattern in dangerous_patterns:
        features.append(1 if re.search(pattern, code) else 0)
    
    # 15-18: Safe function patterns
    safe_patterns = [
        r'\bstrncpy\s*\(',
        r'\bfgets\s*\(',
        r'\bsnprintf\s*\(',
        r'\bstrncat\s*\(',
    ]
    
    for pattern in safe_patterns:
        features.append(1 if re.search(pattern, code) else 0)
    
    # 19-22: Sanitization indicators
    features.append(1 if re.search(r'\bvalidate\b', code, re.I) else 0)
    features.append(1 if re.search(r'\bsanitize\b', code, re.I) else 0)
    features.append(1 if re.search(r'\bstrlen\b', code) else 0)
    features.append(1 if re.search(r'\bsizeof\b', code) else 0)
    
    # 23-25: Pointer operations
    features.append(min(code.count('->'), 50))
    features.append(min(code.count('*'), 50))
    features.append(min(code.count('&'), 50))
    
    # 26-27: Array operations
    features.append(min(code.count('['), 50))
    features.append(min(code.count(']'), 50))
    
    # 28-30: Control flow complexity
    features.append(min(code.count('if'), 50))
    features.append(min(code.count('for'), 50))
    features.append(min(code.count('while'), 50))
    
    # 31-32: Comments
    features.append(min(code.count('//'), 50))
    features.append(min(code.count('/*'), 50))
    
    # 33-34: Additional metrics
    features.append(min(code.count('NULL'), 20))
    features.append(min(code.count('return'), 20))
    
    return np.array(features).reshape(1, -1)

@app.route('/', methods=['GET'])
def home():
    """Home endpoint"""
    return jsonify({
        "service": "Vulnerability Detection API",
        "version": "1.0.0",
        "model": "XGBoost",
        "accuracy": "99.99%",
        "university": "ESPE",
        "project": "CI/CD Security Pipeline",
        "status": "online",
        "endpoints": {
            "health": "/health",
            "analyze": "/analyze (POST)",
            "info": "/info"
        }
    })

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for Render"""
    return jsonify({
        "status": "ok",
        "model_loaded": MODEL is not None,
        "timestamp": datetime.utcnow().isoformat()
    }), 200

@app.route('/info', methods=['GET'])
def info():
    """Model information endpoint"""
    return jsonify({
        "model_type": "XGBoost Classifier",
        "accuracy": "99.99%",
        "dataset": "DiverseVul + BigVul + CVE (38,294 samples)",
        "features": 34,
        "classes": ["SAFE", "VULNERABLE"],
        "complies_with": "ESPE Project Requirements (No LLMs)",
        "trained_date": "2025-12-16"
    })

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze code for vulnerabilities"""
    try:
        if MODEL is None:
            return jsonify({
                "error": "Model not loaded",
                "status": "error"
            }), 500
        
        # Get code from request
        data = request.get_json()
        if not data or 'code' not in data:
            return jsonify({
                "error": "Missing 'code' field in request body",
                "status": "error"
            }), 400
        
        code = data['code']
        
        if not code or len(code.strip()) == 0:
            return jsonify({
                "error": "Code cannot be empty",
                "status": "error"
            }), 400
        
        # Extract features
        features = extract_features(code)
        features_scaled = SCALER.transform(features)
        
        # Predict
        prediction = MODEL.predict(features_scaled)[0]
        probabilities = MODEL.predict_proba(features_scaled)[0]
        
        # Get class label
        classification = LABEL_ENCODER.inverse_transform([prediction])[0]
        confidence = float(max(probabilities)) * 100
        
        # Detect specific vulnerabilities
        vulnerabilities = []
        if re.search(r'\bstrcpy\s*\(', code):
            vulnerabilities.append("CWE-787: Buffer Overflow (strcpy)")
        if re.search(r'\bgets\s*\(', code):
            vulnerabilities.append("CWE-676: Dangerous Function (gets)")
        if re.search(r'\bsystem\s*\(', code):
            vulnerabilities.append("CWE-78: Command Injection (system)")
        if re.search(r'\bsprintf\s*\(', code):
            vulnerabilities.append("CWE-134: Format String (sprintf)")
        
        return jsonify({
            "status": "success",
            "classification": classification,
            "confidence": round(confidence, 2),
            "is_vulnerable": classification == "VULNERABLE",
            "vulnerabilities": vulnerabilities if classification == "VULNERABLE" else [],
            "timestamp": datetime.utcnow().isoformat(),
            "model": "XGBoost (99.99% accuracy)"
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "status": "error"
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint not found",
        "status": "error"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": "Internal server error",
        "status": "error"
    }), 500

# Load model on startup
print("Loading ML model...")
if not load_model():
    print("WARNING: Model failed to load, API may not work correctly")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    print(f"Starting Vulnerability Detection API on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
