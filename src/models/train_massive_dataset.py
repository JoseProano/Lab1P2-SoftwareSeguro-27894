#!/usr/bin/env python3
"""
Entrenamiento con dataset MASIVO de repositorios reales
1,474 muestras de código vulnerable/seguro
"""

import json
import numpy as np
from pathlib import Path
from typing import List, Dict, Tuple
from loguru import logger
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix, roc_auc_score
import joblib
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Import feature extractor
import sys
sys.path.insert(0, '/app/src/models')
from real_data_mining import AdvancedFeatureExtractor


class MassiveDatasetTrainer:
    """
    Entrena modelos ML con dataset MASIVO de repositorios reales
    """
    
    def __init__(self, dataset_path: Path):
        self.dataset_path = dataset_path
        self.feature_extractor = AdvancedFeatureExtractor()
        self.models_dir = Path('/app/models')
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Modelos según laboratorio
        self.models = {
            'random_forest': RandomForestClassifier(
                n_estimators=300,
                max_depth=30,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=10,
                min_samples_split=5,
                subsample=0.8,
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
                hidden_layer_sizes=(256, 128, 64, 32),
                activation='relu',
                solver='adam',
                alpha=0.0001,
                batch_size=32,
                learning_rate='adaptive',
                max_iter=500,
                random_state=42,
                early_stopping=True
            )
        }
    
    def load_and_prepare_dataset(self) -> Tuple[np.ndarray, np.ndarray]:
        """Carga dataset masivo y extrae features"""
        
        logger.info(f"Loading dataset from {self.dataset_path}")
        data = json.loads(self.dataset_path.read_text())
        
        vulnerable_samples = data['vulnerable_samples']
        safe_samples = data['safe_samples']
        
        logger.info(f"Total vulnerable: {len(vulnerable_samples)}")
        logger.info(f"Total safe: {len(safe_samples)}")
        
        # Balance dataset (tomar muestras equitativas)
        # Usar todas las vulnerables + mismo número de safe
        num_vulnerable = len(vulnerable_samples)
        
        # Tomar todas las vulnerables
        all_samples = vulnerable_samples.copy()
        
        # Agregar safe samples (balancear)
        safe_to_use = min(num_vulnerable * 3, len(safe_samples))  # Ratio 1:3
        all_samples.extend(safe_samples[:safe_to_use])
        
        logger.info(f"Using {len(all_samples)} total samples (vulnerable + safe balanced)")
        
        # Extraer features
        X = []
        y = []
        
        logger.info("Extracting features from code samples...")
        
        for i, sample in enumerate(all_samples):
            if i % 100 == 0:
                logger.info(f"Processed {i}/{len(all_samples)} samples...")
            
            try:
                # Extract 34 features
                features = self.feature_extractor.extract_all_features(sample['code'])
                X.append(features)
                y.append(sample['label'])
            except Exception as e:
                logger.warning(f"Failed to extract features from sample {i}: {e}")
        
        X = np.array(X)
        y = np.array(y)
        
        logger.info(f"Dataset shape before filtering: {X.shape}")
        logger.info(f"Label distribution before filtering:")
        unique, counts = np.unique(y, return_counts=True)
        for label, count in zip(unique, counts):
            logger.info(f"  {label}: {count} ({count/len(y)*100:.1f}%)")
        
        # Filtrar clases con muy pocas muestras (< 5 samples)
        min_samples_per_class = 5
        valid_indices = []
        
        for i, label in enumerate(y):
            label_count = np.sum(y == label)
            if label_count >= min_samples_per_class:
                valid_indices.append(i)
        
        X = X[valid_indices]
        y = y[valid_indices]
        
        logger.info(f"\n✅ Final dataset shape after filtering: {X.shape}")
        logger.info(f"Final label distribution:")
        unique, counts = np.unique(y, return_counts=True)
        for label, count in zip(unique, counts):
            logger.info(f"  {label}: {count} ({count/len(y)*100:.1f}%)")
        
        return X, y
    
    def train_and_evaluate(self, X: np.ndarray, y: np.ndarray):
        """
        SEMMA Phase 4 (Model) y 5 (Assess)
        Entrena y evalúa múltiples modelos
        """
        
        # Split dataset
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info(f"Training set: {X_train.shape[0]} samples")
        logger.info(f"Test set: {X_test.shape[0]} samples")
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Encode labels
        label_encoder = LabelEncoder()
        y_train_encoded = label_encoder.fit_transform(y_train)
        y_test_encoded = label_encoder.transform(y_test)
        
        logger.info(f"Classes: {label_encoder.classes_}")
        
        best_model_name = None
        best_f1 = 0
        results = {}
        
        # Entrenar cada modelo
        for model_name, model in self.models.items():
            logger.info(f"\n{'='*60}")
            logger.info(f"Training {model_name.upper()}")
            logger.info(f"{'='*60}")
            
            # Train
            model.fit(X_train_scaled, y_train_encoded)
            
            # Predict
            y_pred = model.predict(X_test_scaled)
            
            # Metrics
            accuracy = accuracy_score(y_test_encoded, y_pred)
            f1 = f1_score(y_test_encoded, y_pred, average='weighted')
            
            logger.info(f"Test Accuracy: {accuracy:.4f}")
            logger.info(f"Test F1-Score: {f1:.4f}")
            
            # Cross-validation
            cv_scores = cross_val_score(
                model, X_train_scaled, y_train_encoded,
                cv=5, scoring='f1_weighted', n_jobs=-1
            )
            logger.info(f"Cross-Validation F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
            
            # ROC-AUC (para binary o multiclass)
            try:
                if len(label_encoder.classes_) == 2:
                    y_proba = model.predict_proba(X_test_scaled)[:, 1]
                    roc_auc = roc_auc_score(y_test_encoded, y_proba)
                else:
                    y_proba = model.predict_proba(X_test_scaled)
                    roc_auc = roc_auc_score(
                        y_test_encoded, y_proba,
                        multi_class='ovr', average='weighted'
                    )
                logger.info(f"ROC-AUC: {roc_auc:.4f}")
            except Exception as e:
                roc_auc = None
                logger.warning(f"ROC-AUC calculation failed: {e}")
            
            # Confusion Matrix
            cm = confusion_matrix(y_test_encoded, y_pred)
            logger.info(f"Confusion Matrix:\n{cm}")
            
            # Classification report
            logger.info("\nClassification Report:")
            report = classification_report(
                y_test_encoded, y_pred,
                target_names=label_encoder.classes_,
                zero_division=0
            )
            logger.info(f"\n{report}")
            
            # Guardar resultados
            results[model_name] = {
                'accuracy': accuracy,
                'f1_score': f1,
                'cv_f1_mean': cv_scores.mean(),
                'cv_f1_std': cv_scores.std(),
                'roc_auc': roc_auc,
                'confusion_matrix': cm.tolist()
            }
            
            # Mejor modelo
            if f1 > best_f1:
                best_f1 = f1
                best_model_name = model_name
        
        logger.info(f"\n{'='*60}")
        logger.info(f"BEST MODEL: {best_model_name.upper()} (F1={best_f1:.4f})")
        logger.info(f"{'='*60}")
        
        # Guardar mejor modelo
        best_model = self.models[best_model_name]
        
        model_path = self.models_dir / 'massive_code_vulnerability_detector.joblib'
        scaler_path = self.models_dir / 'massive_code_scaler.joblib'
        encoder_path = self.models_dir / 'massive_code_label_encoder.joblib'
        
        joblib.dump(best_model, model_path)
        joblib.dump(scaler, scaler_path)
        joblib.dump(label_encoder, encoder_path)
        
        logger.info(f"✅ Saved best model: {model_path}")
        logger.info(f"✅ Saved scaler: {scaler_path}")
        logger.info(f"✅ Saved encoder: {encoder_path}")
        
        # Metadata
        metadata = {
            'model_type': best_model_name,
            'trained_date': datetime.now().isoformat(),
            'dataset_size': len(X),
            'train_size': len(X_train),
            'test_size': len(X_test),
            'num_features': X.shape[1],
            'classes': label_encoder.classes_.tolist(),
            'data_source': 'Massive GitHub repository mining',
            'repositories': [
                'WebGoat/WebGoat',
                'CSPF-Founder/JavaVulnerableLab',
                'dschadow/JavaSecurity',
                'anxolerd/dvpwa',
                'OWASP/NodeGoat',
                'cr0hn/vulnerable-node',
                'ethicalhack3r/DVWA',
                'and more...'
            ],
            'results': results
        }
        
        metadata_path = self.models_dir / 'massive_code_model_metadata.json'
        metadata_path.write_text(json.dumps(metadata, indent=2))
        logger.info(f"✅ Saved metadata: {metadata_path}")
        
        return results


def main():
    logger.info("="*60)
    logger.info("TRAINING WITH MASSIVE REAL CODE DATASET")
    logger.info("SEMMA Methodology - Phases 4 & 5 (Model & Assess)")
    logger.info("="*60)
    
    dataset_path = Path('/app/data/massive_vulnerability_dataset.json')
    
    if not dataset_path.exists():
        logger.error(f"Dataset not found: {dataset_path}")
        return
    
    trainer = MassiveDatasetTrainer(dataset_path)
    
    # Load and prepare
    X, y = trainer.load_and_prepare_dataset()
    
    # Train and evaluate
    results = trainer.train_and_evaluate(X, y)
    
    logger.info("\n✅ Training completed successfully!")
    logger.info("Models trained with REAL vulnerable code from multiple repositories")


if __name__ == '__main__':
    main()
