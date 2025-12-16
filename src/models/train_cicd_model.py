#!/usr/bin/env python3
"""
Entrena modelo optimizado para CI/CD (>82% accuracy requerido)
Usa ensemble stacking para maximizar accuracy
"""

import json
import numpy as np
from pathlib import Path
from typing import Tuple
from loguru import logger
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix, roc_auc_score, precision_score, recall_score
import joblib
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Import feature extractor
import sys
from pathlib import Path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / 'src' / 'models'))
from real_data_mining import AdvancedFeatureExtractor


class CICDModelTrainer:
    """
    Entrena modelo OPTIMIZADO para CI/CD
    Objetivo: >82% accuracy en validación cruzada
    """
    
    def __init__(self, dataset_path: Path):
        self.dataset_path = dataset_path
        self.feature_extractor = AdvancedFeatureExtractor()
        project_root = Path(__file__).parent.parent.parent
        self.models_dir = project_root / 'models'
        self.models_dir.mkdir(parents=True, exist_ok=True)
    
    def load_and_prepare_dataset(self, max_samples: int = 30000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Carga dataset con MÁS muestras para mejor entrenamiento
        """
        logger.info(f"Loading dataset from {self.dataset_path}")
        data = json.loads(self.dataset_path.read_text())
        
        all_samples = data['samples']
        vulnerable = [s for s in all_samples if s['vulnerable']]
        safe = [s for s in all_samples if not s['vulnerable']]
        
        # Usar MÁS datos (30K total)
        half = max_samples // 2
        samples = vulnerable[:half] + safe[:half]
        
        import random
        random.seed(42)
        random.shuffle(samples)
        
        logger.info(f"Using {len(samples)} samples ({half} vulnerable + {half} safe)")
        
        X = []
        y = []
        
        logger.info("Extracting features from C/C++ code...")
        
        for i, sample in enumerate(samples):
            if i % 2000 == 0:
                logger.info(f"Processed {i}/{len(samples)} samples...")
            
            try:
                features = self.feature_extractor.extract_all_features(sample['code'])
                X.append(features)
                
                label = 'VULNERABLE' if sample['vulnerable'] else 'SAFE'
                y.append(label)
            except Exception as e:
                continue
        
        X = np.array(X)
        y = np.array(y)
        
        logger.info(f"✅ Final dataset shape: {X.shape}")
        logger.info(f"Label distribution:")
        unique, counts = np.unique(y, return_counts=True)
        for label, count in zip(unique, counts):
            logger.info(f"  {label}: {count} ({count/len(y)*100:.1f}%)")
        
        return X, y
    
    def train_ensemble_model(self, X: np.ndarray, y: np.ndarray):
        """
        Entrena ENSEMBLE de modelos para maximizar accuracy
        """
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info(f"Training set: {X_train.shape[0]} samples")
        logger.info(f"Test set: {X_test.shape[0]} samples")
        
        # Scale
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Encode
        label_encoder = LabelEncoder()
        y_train_encoded = label_encoder.fit_transform(y_train)
        y_test_encoded = label_encoder.transform(y_test)
        
        logger.info(f"Classes: {label_encoder.classes_}")
        
        # =====================================================
        # ESTRATEGIA 1: VOTING ENSEMBLE (múltiples modelos)
        # =====================================================
        logger.info("\n" + "="*60)
        logger.info("TRAINING VOTING ENSEMBLE")
        logger.info("="*60)
        
        rf = RandomForestClassifier(
            n_estimators=800,
            max_depth=60,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        gb = GradientBoostingClassifier(
            n_estimators=500,
            learning_rate=0.03,
            max_depth=20,
            min_samples_split=5,
            subsample=0.9,
            random_state=42
        )
        
        svm = SVC(
            C=2.0,
            kernel='rbf',
            gamma='scale',
            class_weight='balanced',
            probability=True,
            random_state=42
        )
        
        nn = MLPClassifier(
            hidden_layer_sizes=(1024, 512, 256, 128),
            activation='relu',
            solver='adam',
            alpha=0.00005,
            batch_size=256,
            learning_rate='adaptive',
            learning_rate_init=0.002,
            max_iter=150,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.15
        )
        
        # VOTING: combina predicciones de todos
        voting_clf = VotingClassifier(
            estimators=[
                ('rf', rf),
                ('gb', gb),
                ('svm', svm),
                ('nn', nn)
            ],
            voting='soft',  # usa probabilidades
            n_jobs=-1
        )
        
        logger.info("Training Voting Ensemble (this may take 5-10 minutes)...")
        voting_clf.fit(X_train_scaled, y_train_encoded)
        
        # Predicción
        y_pred = voting_clf.predict(X_test_scaled)
        y_proba = voting_clf.predict_proba(X_test_scaled)[:, 1]
        
        # Métricas
        accuracy = accuracy_score(y_test_encoded, y_pred)
        f1 = f1_score(y_test_encoded, y_pred, average='weighted')
        precision = precision_score(y_test_encoded, y_pred, average='weighted')
        recall = recall_score(y_test_encoded, y_pred, average='weighted')
        roc_auc = roc_auc_score(y_test_encoded, y_proba)
        
        logger.info(f"\n{'='*60}")
        logger.info(f"VOTING ENSEMBLE RESULTS")
        logger.info(f"{'='*60}")
        logger.info(f"Test Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        logger.info(f"Test F1-Score: {f1:.4f}")
        logger.info(f"Test Precision: {precision:.4f}")
        logger.info(f"Test Recall: {recall:.4f}")
        logger.info(f"ROC-AUC: {roc_auc:.4f}")
        
        # Cross-validation
        logger.info("\nPerforming 5-Fold Cross-Validation...")
        cv_scores = cross_val_score(
            voting_clf, X_train_scaled, y_train_encoded,
            cv=5, scoring='accuracy', n_jobs=-1, verbose=1
        )
        logger.info(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        logger.info(f"CV Scores: {cv_scores}")
        
        cm = confusion_matrix(y_test_encoded, y_pred)
        logger.info(f"\nConfusion Matrix:\n{cm}")
        
        report = classification_report(
            y_test_encoded, y_pred,
            target_names=label_encoder.classes_,
            zero_division=0
        )
        logger.info(f"\n{report}")
        
        # =====================================================
        # VERIFICAR SI CUMPLE REQUISITO: >82% accuracy
        # =====================================================
        if cv_scores.mean() >= 0.82:
            logger.info(f"\n{'='*60}")
            logger.info(f"✅ MODEL MEETS REQUIREMENT: {cv_scores.mean()*100:.2f}% >= 82%")
            logger.info(f"{'='*60}")
        else:
            logger.warning(f"\n{'='*60}")
            logger.warning(f"⚠️  MODEL BELOW REQUIREMENT: {cv_scores.mean()*100:.2f}% < 82%")
            logger.warning(f"Consider: More data, feature engineering, or hyperparameter tuning")
            logger.warning(f"{'='*60}")
        
        # Guardar modelo
        model_path = self.models_dir / 'cicd_vulnerability_detector.joblib'
        scaler_path = self.models_dir / 'cicd_scaler.joblib'
        encoder_path = self.models_dir / 'cicd_label_encoder.joblib'
        
        joblib.dump(voting_clf, model_path)
        joblib.dump(scaler, scaler_path)
        joblib.dump(label_encoder, encoder_path)
        
        logger.info(f"\n✅ Model saved: {model_path}")
        logger.info(f"✅ Scaler saved: {scaler_path}")
        logger.info(f"✅ Encoder saved: {encoder_path}")
        
        # Metadata para CI/CD
        metadata = {
            'model_type': 'voting_ensemble',
            'ensemble_models': ['RandomForest', 'GradientBoosting', 'SVM', 'NeuralNetwork'],
            'trained_date': datetime.now().isoformat(),
            'dataset_size': len(X),
            'train_size': len(X_train),
            'test_size': len(X_test),
            'num_features': X.shape[1],
            'classes': label_encoder.classes_.tolist(),
            'data_source': 'DiverseVul + BigVul (45,830 samples)',
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
                'random_forest': {
                    'n_estimators': 800,
                    'max_depth': 60,
                    'min_samples_split': 5
                },
                'gradient_boosting': {
                    'n_estimators': 500,
                    'learning_rate': 0.03,
                    'max_depth': 20
                },
                'svm': {
                    'C': 2.0,
                    'kernel': 'rbf'
                },
                'neural_network': {
                    'hidden_layers': [1024, 512, 256, 128],
                    'learning_rate': 0.002,
                    'max_iter': 150
                }
            }
        }
        
        metadata_path = self.models_dir / 'cicd_model_metadata.json'
        metadata_path.write_text(json.dumps(metadata, indent=2))
        logger.info(f"✅ Metadata saved: {metadata_path}")
        
        return metadata


def main():
    logger.info("="*60)
    logger.info("CI/CD MODEL TRAINING")
    logger.info("Target: >82% Accuracy (Cross-Validation)")
    logger.info("Dataset: 30,000 samples (15K vulnerable + 15K safe)")
    logger.info("="*60)
    
    project_root = Path(__file__).parent.parent.parent
    dataset_path = project_root / 'data' / 'professional_vulnerability_dataset.json'
    
    if not dataset_path.exists():
        logger.error(f"Dataset not found: {dataset_path}")
        logger.error("Run process_professional_datasets.py first!")
        return
    
    trainer = CICDModelTrainer(dataset_path)
    
    # Load dataset (30K samples para mejor accuracy)
    X, y = trainer.load_and_prepare_dataset(max_samples=30000)
    
    # Train ensemble
    metadata = trainer.train_ensemble_model(X, y)
    
    logger.info("\n" + "="*60)
    logger.info("TRAINING COMPLETED!")
    logger.info(f"CV Accuracy: {metadata['metrics']['cv_accuracy_mean']*100:.2f}%")
    logger.info(f"Test Accuracy: {metadata['metrics']['test_accuracy']*100:.2f}%")
    logger.info(f"Meets Requirement: {metadata['meets_requirement']}")
    logger.info("="*60)


if __name__ == '__main__':
    main()
