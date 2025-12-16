#!/usr/bin/env python3
"""
Entrenamiento rápido del modelo usando datos ya preprocesados
"""

import numpy as np
from pathlib import Path
from loguru import logger
from sklearn.model_selection import cross_val_score
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix, roc_auc_score, precision_score, recall_score
from xgboost import XGBClassifier
import joblib
import json
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

project_root = Path(__file__).parent.parent.parent
models_dir = project_root / 'models'
models_dir.mkdir(parents=True, exist_ok=True)

def main():
    logger.info("="*60)
    logger.info("FAST CI/CD MODEL TRAINING")
    logger.info("Using: Pre-processed numpy data + XGBoost")
    logger.info("Target: >82% CV Accuracy")
    logger.info("="*60)
    
    # Load data
    logger.info("\nLoading pre-processed data...")
    X_train = np.load(project_root / 'data' / 'X_train.npy')
    y_train = np.load(project_root / 'data' / 'y_train.npy')
    X_test = np.load(project_root / 'data' / 'X_test.npy')
    y_test = np.load(project_root / 'data' / 'y_test.npy')
    
    logger.info(f"Training set: {X_train.shape[0]} samples, {X_train.shape[1]} features")
    logger.info(f"Test set: {X_test.shape[0]} samples")
    
    unique, counts = np.unique(y_train, return_counts=True)
    logger.info(f"Training distribution: {dict(zip(unique, counts))}")
    
    # Train XGBoost
    logger.info("\n" + "="*60)
    logger.info("TRAINING XGBOOST MODEL")
    logger.info("="*60)
    
    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        random_state=42,
        n_jobs=-1,
        eval_metric='logloss'
    )
    
    logger.info("Training... (this will take 2-3 minutes)")
    model.fit(X_train, y_train)
    
    # Predictions
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)
    
    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='weighted')
    precision = precision_score(y_test, y_pred, average='weighted')
    recall = recall_score(y_test, y_pred, average='weighted')
    roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])
    
    logger.info("\n" + "="*60)
    logger.info("TEST SET RESULTS")
    logger.info("="*60)
    logger.info(f"Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    logger.info(f"F1-Score: {f1:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall: {recall:.4f}")
    logger.info(f"ROC-AUC: {roc_auc:.4f}")
    
    # Cross-validation on training set
    logger.info("\n" + "="*60)
    logger.info("CROSS-VALIDATION (5-Fold)")
    logger.info("="*60)
    logger.info("Running CV... (this will take 5-10 minutes)")
    
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, n_jobs=-1, verbose=0)
    
    logger.info(f"\nCV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    logger.info(f"CV Scores per fold: {[f'{s:.4f}' for s in cv_scores]}")
    logger.info(f"Mean: {cv_scores.mean()*100:.2f}%")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    logger.info(f"\nConfusion Matrix:\n{cm}")
    logger.info(f"\n{classification_report(y_test, y_pred, target_names=['SAFE', 'VULNERABLE'])}")
    
    # Check requirement
    if cv_scores.mean() >= 0.82:
        logger.info("\n" + "="*60)
        logger.info(f"✅ MODEL MEETS REQUIREMENT!")
        logger.info(f"CV Accuracy: {cv_scores.mean()*100:.2f}% >= 82%")
        logger.info("="*60)
    else:
        logger.warning("\n" + "="*60)
        logger.warning(f"⚠️  MODEL BELOW REQUIREMENT")
        logger.warning(f"CV Accuracy: {cv_scores.mean()*100:.2f}% < 82%")
        logger.warning("="*60)
    
    # Save model
    model_path = models_dir / 'cicd_vulnerability_detector.joblib'
    joblib.dump(model, model_path)
    logger.info(f"\n✅ Model saved: {model_path}")
    
    # Save simple scaler and encoder (identity for pre-processed data)
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    scaler = StandardScaler()
    scaler.mean_ = np.zeros(X_train.shape[1])
    scaler.scale_ = np.ones(X_train.shape[1])
    scaler.n_features_in_ = X_train.shape[1]
    
    encoder = LabelEncoder()
    encoder.classes_ = np.array(['SAFE', 'VULNERABLE'])
    
    scaler_path = models_dir / 'cicd_scaler.joblib'
    encoder_path = models_dir / 'cicd_label_encoder.joblib'
    
    joblib.dump(scaler, scaler_path)
    joblib.dump(encoder, encoder_path)
    
    logger.info(f"✅ Scaler saved: {scaler_path}")
    logger.info(f"✅ Encoder saved: {encoder_path}")
    
    # Metadata
    metadata = {
        'model_type': 'xgboost',
        'trained_date': datetime.now().isoformat(),
        'dataset_size': len(X_train) + len(X_test),
        'train_size': len(X_train),
        'test_size': len(X_test),
        'num_features': X_train.shape[1],
        'classes': ['SAFE', 'VULNERABLE'],
        'data_source': 'Real vulnerability dataset (pre-processed)',
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
        'hyperparameters': {
            'n_estimators': 300,
            'max_depth': 8,
            'learning_rate': 0.1,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'min_child_weight': 3,
            'gamma': 0.1,
            'reg_alpha': 0.1,
            'reg_lambda': 1.0
        }
    }
    
    metadata_path = models_dir / 'cicd_model_metadata.json'
    metadata_path.write_text(json.dumps(metadata, indent=2))
    logger.info(f"✅ Metadata saved: {metadata_path}")
    
    logger.info("\n" + "="*60)
    logger.info("TRAINING COMPLETED!")
    logger.info(f"Final CV Accuracy: {cv_scores.mean()*100:.2f}%")
    logger.info(f"Final Test Accuracy: {accuracy*100:.2f}%")
    logger.info(f"Meets Requirement (>82%): {metadata['meets_requirement']}")
    logger.info("="*60)
    
    return metadata

if __name__ == '__main__':
    main()
