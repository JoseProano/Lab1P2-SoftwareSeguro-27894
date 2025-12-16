#!/usr/bin/env python3
"""
Entrenamiento del modelo ML optimizado para CI/CD
Objetivo: Superar 82% accuracy con XGBoost optimizado
"""

import json
import numpy as np
from pathlib import Path
from typing import Tuple
from loguru import logger
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

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except:
    HAS_XGBOOST = False
    logger.warning("XGBoost not available, will use alternatives")


class ImprovedCICDTrainer:
    """
    Entrenador mejorado con XGBoost optimizado
    """
    
    def __init__(self, dataset_path: Path):
        self.dataset_path = dataset_path
        self.feature_extractor = AdvancedFeatureExtractor()
        self.models_dir = project_root / 'models'
        self.models_dir.mkdir(parents=True, exist_ok=True)
    
    def load_and_prepare_dataset(self, max_samples: int = 20000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Carga dataset massive con mejor calidad
        """
        logger.info(f"Loading dataset from {self.dataset_path}")
        data = json.loads(self.dataset_path.read_text())
        
        # Dataset tiene estructura diferente
        vulnerable_samples = data['vulnerable_samples'][:max_samples//2]
        safe_samples = data['safe_samples'][:max_samples//2]
        
        logger.info(f"Using {len(vulnerable_samples)} vulnerable + {len(safe_samples)} safe samples")
        
        # Extract features
        logger.info("Extracting features from C/C++ code...")
        X_list = []
        y_list = []
        
        for i, sample in enumerate(vulnerable_samples + safe_samples):
            if i % 2000 == 0:
                logger.info(f"Processed {i}/{len(vulnerable_samples) + len(safe_samples)} samples...")
            
            code = sample.get('code', sample.get('function', ''))
            features = self.feature_extractor.extract_all_features(code)
            X_list.append(features)
            y_list.append('VULNERABLE' if sample.get('vulnerable', sample.get('label') == 1) else 'SAFE')
        
        X = np.array(X_list)
        y = np.array(y_list)
        
        logger.info(f"✅ Final dataset shape: {X.shape}")
        unique, counts = np.unique(y, return_counts=True)
        logger.info("Label distribution:")
        for label, count in zip(unique, counts):
            logger.info(f"  {label}: {count} ({count/len(y)*100:.1f}%)")
        
        return X, y
    
    def train_xgboost_model(self, X: np.ndarray, y: np.ndarray):
        """
        Entrena XGBoost optimizado (mejor que ensemble para este caso)
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
        
        logger.info(f"Training set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        logger.info(f"Classes: {label_encoder.classes_}")
        
        logger.info("\n" + "="*60)
        logger.info("TRAINING XGBOOST OPTIMIZED MODEL")
        logger.info("="*60)
        
        # XGBoost with optimized hyperparameters
        model = XGBClassifier(
            n_estimators=500,
            max_depth=10,
            learning_rate=0.05,
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
        
        logger.info("Training XGBoost (this may take 3-5 minutes)...")
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
        logger.info("XGBOOST RESULTS")
        logger.info("="*60)
        logger.info(f"Test Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        logger.info(f"Test F1-Score: {f1:.4f}")
        logger.info(f"Test Precision: {precision:.4f}")
        logger.info(f"Test Recall: {recall:.4f}")
        logger.info(f"ROC-AUC: {roc_auc:.4f}")
        
        # Cross-validation
        logger.info("\nPerforming 5-Fold Cross-Validation...")
        cv_scores = cross_val_score(model, X_train_scaled, y_train_encoded, cv=5, n_jobs=-1, verbose=0)
        
        logger.info(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        logger.info(f"CV Scores: {cv_scores}")
        
        # Confusion matrix
        cm = confusion_matrix(y_test_encoded, y_pred)
        logger.info(f"\nConfusion Matrix:\n{cm}")
        logger.info(f"\n{classification_report(y_test_encoded, y_pred, target_names=label_encoder.classes_)}")
        
        # Check requirement
        if cv_scores.mean() >= 0.82:
            logger.info(f"\n{'='*60}")
            logger.info(f"✅ MODEL MEETS REQUIREMENT: {cv_scores.mean()*100:.2f}% >= 82%")
            logger.info(f"{'='*60}")
        else:
            logger.warning(f"\n{'='*60}")
            logger.warning(f"⚠️  MODEL BELOW REQUIREMENT: {cv_scores.mean()*100:.2f}% < 82%")
            logger.warning(f"Note: This may be due to dataset quality issues")
            logger.warning(f"{'='*60}")
        
        # Save model
        model_path = self.models_dir / 'cicd_vulnerability_detector.joblib'
        scaler_path = self.models_dir / 'cicd_scaler.joblib'
        encoder_path = self.models_dir / 'cicd_label_encoder.joblib'
        
        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)
        joblib.dump(label_encoder, encoder_path)
        
        logger.info(f"\n✅ Model saved: {model_path}")
        logger.info(f"✅ Scaler saved: {scaler_path}")
        logger.info(f"✅ Encoder saved: {encoder_path}")
        
        # Metadata
        metadata = {
            'model_type': 'xgboost_optimized',
            'trained_date': datetime.now().isoformat(),
            'dataset_size': len(X),
            'train_size': len(X_train),
            'test_size': len(X_test),
            'num_features': X.shape[1],
            'classes': label_encoder.classes_.tolist(),
            'data_source': 'Massive Vulnerability Dataset (real C/C++ vulnerabilities)',
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
            'note': 'XGBoost optimized for code vulnerability detection',
            'hyperparameters': {
                'n_estimators': 500,
                'max_depth': 10,
                'learning_rate': 0.05,
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'min_child_weight': 3,
                'gamma': 0.1,
                'reg_alpha': 0.1,
                'reg_lambda': 1.0
            }
        }
        
        metadata_path = self.models_dir / 'cicd_model_metadata.json'
        metadata_path.write_text(json.dumps(metadata, indent=2))
        logger.info(f"✅ Metadata saved: {metadata_path}")
        
        return metadata


def main():
    logger.info("="*60)
    logger.info("IMPROVED CI/CD MODEL TRAINING")
    logger.info("Target: >82% Accuracy (Cross-Validation)")
    logger.info("Using: XGBoost Optimized + Massive Dataset")
    logger.info("="*60)
    
    dataset_path = project_root / 'data' / 'massive_vulnerability_dataset.json'
    
    if not dataset_path.exists():
        logger.error(f"Dataset not found: {dataset_path}")
        return
    
    trainer = ImprovedCICDTrainer(dataset_path)
    
    # Load dataset
    X, y = trainer.load_and_prepare_dataset(max_samples=20000)
    
    # Train XGBoost
    metadata = trainer.train_xgboost_model(X, y)
    
    logger.info("\n" + "="*60)
    logger.info("TRAINING COMPLETED!")
    logger.info(f"CV Accuracy: {metadata['metrics']['cv_accuracy_mean']*100:.2f}%")
    logger.info(f"Test Accuracy: {metadata['metrics']['test_accuracy']*100:.2f}%")
    logger.info(f"Meets Requirement: {metadata['meets_requirement']}")
    logger.info("="*60)


if __name__ == '__main__':
    main()
