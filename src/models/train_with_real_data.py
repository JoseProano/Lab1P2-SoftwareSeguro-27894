#!/usr/bin/env python3
"""
FASE 4 - MODEL (Modelado)
Entrena modelos ML con código REAL extraído

Algoritmos aplicados (según laboratorio):
- Random Forest (clasificación)
- Gradient Boosting
- SVM
- Neural Networks
"""

import numpy as np
import pandas as pd
from pathlib import Path
from loguru import logger
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, f1_score, accuracy_score
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
from datetime import datetime
from collections import Counter

class RealCodeVulnerabilityTrainer:
    """
    FASE 4 - MODEL
    Entrena múltiples modelos con código real
    """
    
    def __init__(self):
        self.models_dir = Path('/app/models')
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Algoritmos según el laboratorio
        self.models = {
            'random_forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42
            ),
            'svm': SVC(
                C=10.0,
                kernel='rbf',
                gamma='scale',
                class_weight='balanced',
                probability=True,
                random_state=42
            ),
            'neural_network': MLPClassifier(
                hidden_layer_sizes=(128, 64, 32),
                activation='relu',
                solver='adam',
                alpha=0.001,
                batch_size=32,
                learning_rate='adaptive',
                max_iter=500,
                random_state=42
            )
        }
    
    def load_dataset(self) -> tuple:
        """Carga dataset generado"""
        dataset_path = Path('/app/data/real_vulnerability_dataset.npz')
        
        if not dataset_path.exists():
            logger.error(f"Dataset not found at {dataset_path}")
            logger.error("Run real_data_mining.py first!")
            raise FileNotFoundError("Dataset not generated")
        
        data = np.load(dataset_path, allow_pickle=True)
        X = data['X']
        y = data['y']
        
        logger.info(f"✅ Loaded dataset: {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"   Label distribution: {Counter(y)}")
        
        return X, y
    
    def train_and_evaluate(self, X, y):
        """
        FASE 4 - MODEL
        FASE 5 - ASSESS (Evaluación)
        Entrena y evalúa todos los modelos
        """
        logger.info("="*60)
        logger.info("FASE 4 - MODEL: Training models with REAL vulnerable code")
        logger.info("="*60)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        logger.info(f"Training set: {X_train.shape[0]} samples")
        logger.info(f"Test set: {X_test.shape[0]} samples")
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Encode labels
        le = LabelEncoder()
        y_train_encoded = le.fit_transform(y_train)
        y_test_encoded = le.transform(y_test)
        
        # Train each model
        results = {}
        
        logger.info("\n" + "="*60)
        logger.info("FASE 5 - ASSESS: Evaluating models")
        logger.info("="*60)
        
        for name, model in self.models.items():
            logger.info(f"\n🔬 Training {name}...")
            
            try:
                # Train
                model.fit(X_train_scaled, y_train_encoded)
                
                # Predict
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = model.predict_proba(X_test_scaled) if hasattr(model, 'predict_proba') else None
                
                # Metrics
                accuracy = accuracy_score(y_test_encoded, y_pred)
                f1 = f1_score(y_test_encoded, y_pred, average='weighted')
                
                # Cross-validation
                cv_scores = cross_val_score(model, X_train_scaled, y_train_encoded, cv=3, scoring='f1_weighted')
                
                # ROC-AUC (solo para clasificación binaria)
                if len(np.unique(y_train_encoded)) == 2 and y_pred_proba is not None:
                    roc_auc = roc_auc_score(y_test_encoded, y_pred_proba[:, 1])
                else:
                    roc_auc = None
                
                results[name] = {
                    'model': model,
                    'accuracy': accuracy,
                    'f1_score': f1,
                    'cv_mean': cv_scores.mean(),
                    'cv_std': cv_scores.std(),
                    'roc_auc': roc_auc
                }
                
                logger.info(f"  ✅ Accuracy: {accuracy:.4f}")
                logger.info(f"  ✅ F1-Score: {f1:.4f}")
                logger.info(f"  ✅ Cross-Validation F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
                if roc_auc:
                    logger.info(f"  ✅ ROC-AUC: {roc_auc:.4f}")
                
                # Confusion matrix
                cm = confusion_matrix(y_test_encoded, y_pred)
                logger.info(f"  Confusion Matrix:\n{cm}")
                
                # Classification report
                report = classification_report(y_test_encoded, y_pred, target_names=le.classes_, zero_division=0)
                logger.info(f"  Classification Report:\n{report}")
                
            except Exception as e:
                logger.error(f"  ❌ Error training {name}: {e}")
                continue
        
        # Select best model
        best_model_name = max(results.keys(), key=lambda k: results[k]['f1_score'])
        best_model = results[best_model_name]['model']
        
        logger.info(f"\n🏆 Best model: {best_model_name}")
        logger.info(f"   F1-Score: {results[best_model_name]['f1_score']:.4f}")
        
        # Save best model
        self.save_models(best_model, scaler, le, best_model_name)
        
        return results, best_model_name
    
    def save_models(self, model, scaler, label_encoder, model_name):
        """Guarda modelos entrenados"""
        logger.info("\n💾 Saving models...")
        
        joblib.dump(model, self.models_dir / 'real_code_vulnerability_detector.joblib')
        joblib.dump(scaler, self.models_dir / 'real_code_scaler.joblib')
        joblib.dump(label_encoder, self.models_dir / 'real_code_label_encoder.joblib')
        
        # Metadata
        metadata = {
            'model_type': model_name,
            'trained_date': datetime.now().isoformat(),
            'training_methodology': 'SEMMA',
            'data_source': 'Real vulnerable code from JavaSpringVulny repository',
            'feature_count': 34,
            'algorithms_tested': list(self.models.keys())
        }
        
        import json
        (self.models_dir / 'real_code_model_metadata.json').write_text(json.dumps(metadata, indent=2))
        
        logger.info(f"✅ Models saved to {self.models_dir}")


def main():
    logger.info("="*60)
    logger.info("TRAINING WITH REAL VULNERABLE CODE")
    logger.info("Methodology: SEMMA (Sample, Explore, Modify, Model, Assess)")
    logger.info("="*60)
    
    trainer = RealCodeVulnerabilityTrainer()
    
    # Load dataset
    X, y = trainer.load_dataset()
    
    # Train and evaluate
    results, best_model = trainer.train_and_evaluate(X, y)
    
    logger.info("\n✅ Training completed!")
    logger.info(f"Best model ({best_model}) ready for production use")
    logger.info("\nNext step: Scan code with trained model")


if __name__ == '__main__':
    main()
