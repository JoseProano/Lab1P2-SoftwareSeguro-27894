#!/usr/bin/env python3
"""
Entrenamiento REALISTA del modelo para CI/CD
Usa solo las 34 features del AdvancedFeatureExtractor (como en producción)
Objetivo: 82-92% accuracy (realista para análisis de vulnerabilidades)
"""

import json
import numpy as np
from pathlib import Path
from loguru import logger
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix, roc_auc_score, precision_score, recall_score
import joblib
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Import feature extractor
import sys
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / 'src' / 'models'))
from real_data_mining import AdvancedFeatureExtractor

models_dir = project_root / 'models'
models_dir.mkdir(parents=True, exist_ok=True)


def load_realistic_dataset(max_samples=15000):
    """
    Carga dataset y extrae SOLO las 34 features que usa el vulnerability_analyzer
    Esto garantiza que el modelo funcione igual en producción
    """
    logger.info("Loading dataset...")
    dataset_path = project_root / 'data' / 'professional_vulnerability_dataset.json'
    
    if not dataset_path.exists():
        logger.error(f"Dataset not found: {dataset_path}")
        return None, None
    
    data = json.loads(dataset_path.read_text())
    all_samples = data['samples']
    
    vulnerable = [s for s in all_samples if s['vulnerable']][:max_samples//2]
    safe = [s for s in all_samples if not s['vulnerable']][:max_samples//2]
    
    logger.info(f"Using {len(vulnerable)} vulnerable + {len(safe)} safe samples")
    
    # Extract ONLY the 34 features
    feature_extractor = AdvancedFeatureExtractor()
    X_list = []
    y_list = []
    
    for i, sample in enumerate(vulnerable + safe):
        if i % 2000 == 0 and i > 0:
            logger.info(f"Processed {i}/{len(vulnerable) + len(safe)} samples...")
        
        code = sample['code']
        features = feature_extractor.extract_all_features(code)
        X_list.append(features)
        y_list.append('VULNERABLE' if sample['vulnerable'] else 'SAFE')
    
    X = np.array(X_list)
    y = np.array(y_list)
    
    logger.info(f"✅ Dataset shape: {X.shape} (34 features como en producción)")
    unique, counts = np.unique(y, return_counts=True)
    logger.info("Label distribution:")
    for label, count in zip(unique, counts):
        logger.info(f"  {label}: {count} ({count/len(y)*100:.1f}%)")
    
    return X, y


def train_realistic_model(X, y):
    """
    Entrena Random Forest con configuración REALISTA
    No busca 100% - busca 82-92% que es realista para detección de vulnerabilidades
    """
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Encode
    label_encoder = LabelEncoder()
    y_train_encoded = label_encoder.fit_transform(y_train)
    y_test_encoded = label_encoder.transform(y_test)
    
    logger.info(f"\nTraining set: {len(X_train)} samples")
    logger.info(f"Test set: {len(X_test)} samples")
    logger.info(f"Classes: {label_encoder.classes_}")
    
    logger.info("\n" + "="*60)
    logger.info("TRAINING REALISTIC RANDOM FOREST")
    logger.info("Target: 82-92% (realistic for vulnerability detection)")
    logger.info("="*60)
    
    # Random Forest con configuración conservadora (evita overfitting)
    model = RandomForestClassifier(
        n_estimators=200,        # Menos árboles
        max_depth=20,            # Profundidad limitada
        min_samples_split=10,    # Más samples para split
        min_samples_leaf=4,      # Más samples en hojas
        max_features='sqrt',     # Solo sqrt(34) ≈ 6 features por árbol
        bootstrap=True,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    
    logger.info("Training Random Forest...")
    model.fit(X_train_scaled, y_train_encoded)
    
    # Test metrics
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)
    
    accuracy = accuracy_score(y_test_encoded, y_pred)
    f1 = f1_score(y_test_encoded, y_pred, average='weighted')
    precision = precision_score(y_test_encoded, y_pred, average='weighted')
    recall = recall_score(y_test_encoded, y_pred, average='weighted')
    roc_auc = roc_auc_score(y_test_encoded, y_pred_proba[:, 1])
    
    logger.info("\n" + "="*60)
    logger.info("TEST SET RESULTS")
    logger.info("="*60)
    logger.info(f"Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    logger.info(f"F1-Score: {f1:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall: {recall:.4f}")
    logger.info(f"ROC-AUC: {roc_auc:.4f}")
    
    # Cross-validation (el que cuenta para el requisito)
    logger.info("\n" + "="*60)
    logger.info("5-FOLD CROSS-VALIDATION (Required for 82% check)")
    logger.info("="*60)
    logger.info("Running CV...")
    
    cv_scores = cross_val_score(model, X_train_scaled, y_train_encoded, cv=5, n_jobs=-1)
    
    logger.info(f"\nCV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    logger.info(f"CV Scores: {[f'{s:.4f}' for s in cv_scores]}")
    logger.info(f"Mean: {cv_scores.mean()*100:.2f}%")
    
    # Confusion matrix
    cm = confusion_matrix(y_test_encoded, y_pred)
    logger.info(f"\nConfusion Matrix:\n{cm}")
    logger.info(f"\n{classification_report(y_test_encoded, y_pred, target_names=label_encoder.classes_)}")
    
    # Check requirement
    if cv_scores.mean() >= 0.82:
        logger.info("\n" + "="*60)
        logger.info(f"✅ MODEL MEETS REQUIREMENT!")
        logger.info(f"CV Accuracy: {cv_scores.mean()*100:.2f}% >= 82%")
        if cv_scores.mean() < 0.95:
            logger.info(f"✅ Accuracy is realistic (not overfitting)")
        logger.info("="*60)
    else:
        logger.warning("\n" + "="*60)
        logger.warning(f"⚠️  MODEL BELOW REQUIREMENT")
        logger.warning(f"CV Accuracy: {cv_scores.mean()*100:.2f}% < 82%")
        logger.warning("="*60)
    
    # Save model
    model_path = models_dir / 'cicd_vulnerability_detector.joblib'
    scaler_path = models_dir / 'cicd_scaler.joblib'
    encoder_path = models_dir / 'cicd_label_encoder.joblib'
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(label_encoder, encoder_path)
    
    logger.info(f"\n✅ Model saved: {model_path}")
    logger.info(f"✅ Scaler saved: {scaler_path}")
    logger.info(f"✅ Encoder saved: {encoder_path}")
    
    # Feature importance
    feature_names = [
        'num_lines', 'num_tokens', 'num_functions', 'num_loops', 'num_conditions',
        'has_strcpy', 'has_strcat', 'has_sprintf', 'has_gets', 'has_scanf',
        'has_malloc', 'has_free', 'has_memcpy', 'has_system', 'has_exec',
        'has_pointer_arithmetic', 'has_type_cast', 'has_buffer_declaration',
        'has_array_access', 'has_null_check', 'has_bounds_check',
        'has_input_validation', 'has_sanitization', 'has_error_handling',
        'cyclomatic_complexity', 'max_nesting_level', 'num_parameters',
        'num_variables', 'has_recursion', 'has_goto', 'has_break_continue',
        'has_switch', 'has_typedef', 'has_struct'
    ]
    
    importances = model.feature_importances_
    top_indices = np.argsort(importances)[-10:][::-1]
    
    logger.info("\n" + "="*60)
    logger.info("TOP 10 MOST IMPORTANT FEATURES")
    logger.info("="*60)
    for idx in top_indices:
        logger.info(f"{feature_names[idx]}: {importances[idx]:.4f}")
    
    # Metadata
    metadata = {
        'model_type': 'random_forest',
        'trained_date': datetime.now().isoformat(),
        'dataset_size': len(X),
        'train_size': len(X_train),
        'test_size': len(X_test),
        'num_features': 34,
        'feature_extraction': 'AdvancedFeatureExtractor (same as production)',
        'classes': label_encoder.classes_.tolist(),
        'data_source': 'DiverseVul + BigVul (professional dataset)',
        'metrics': {
            'test_accuracy': float(accuracy),
            'test_f1_score': float(f1),
            'test_precision': float(precision),
            'test_recall': float(recall),
            'roc_auc': float(roc_auc),
            'cv_accuracy_mean': float(cv_scores.mean()),
            'cv_accuracy_std': float(cv_scores.std()),
            'cv_scores': cv_scores.tolist(),
            'confusion_matrix': cm.tolist()
        },
        'meets_requirement': bool(cv_scores.mean() >= 0.82),
        'requirement': '82% accuracy minimum for CI/CD',
        'is_realistic': cv_scores.mean() < 0.95,
        'note': 'Model uses same 34 features as vulnerability_analyzer.py in production',
        'hyperparameters': {
            'n_estimators': 200,
            'max_depth': 20,
            'min_samples_split': 10,
            'min_samples_leaf': 4,
            'max_features': 'sqrt',
            'class_weight': 'balanced'
        },
        'top_features': {feature_names[idx]: float(importances[idx]) for idx in top_indices}
    }
    
    metadata_path = models_dir / 'cicd_model_metadata.json'
    metadata_path.write_text(json.dumps(metadata, indent=2))
    logger.info(f"✅ Metadata saved: {metadata_path}")
    
    logger.info("\n" + "="*60)
    logger.info("TRAINING COMPLETED!")
    logger.info(f"Final CV Accuracy: {cv_scores.mean()*100:.2f}%")
    logger.info(f"Final Test Accuracy: {accuracy*100:.2f}%")
    logger.info(f"Meets Requirement (>82%): {metadata['meets_requirement']}")
    logger.info(f"Realistic (not overfitting): {metadata['is_realistic']}")
    logger.info("="*60)
    
    return metadata


def main():
    logger.info("="*60)
    logger.info("REALISTIC CI/CD MODEL TRAINING")
    logger.info("Using: 34 features (same as production)")
    logger.info("Target: 82-92% (realistic accuracy)")
    logger.info("="*60)
    
    X, y = load_realistic_dataset(max_samples=15000)
    
    if X is None:
        return
    
    metadata = train_realistic_model(X, y)


if __name__ == '__main__':
    main()
