#!/usr/bin/env python3
"""
Entrenamiento con dataset PROFESIONAL de 45,830 muestras
DiverseVul + BigVul = Código vulnerable REAL académico
"""

import json
import numpy as np
from pathlib import Path
from typing import Tuple
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

# Import feature extractor para C
import sys
sys.path.insert(0, '/app/src/models')
from real_data_mining import AdvancedFeatureExtractor


class ProfessionalVulnerabilityTrainer:
    """
    Entrena con 45K+ muestras de DiverseVul + BigVul
    """
    
    def __init__(self, dataset_path: Path):
        self.dataset_path = dataset_path
        self.feature_extractor = AdvancedFeatureExtractor()
        self.models_dir = Path('/app/models')
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Modelos optimizados para dataset grande
        self.models = {
            'random_forest': RandomForestClassifier(
                n_estimators=500,
                max_depth=50,
                min_samples_split=10,
                min_samples_leaf=4,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1,
                verbose=1
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=300,
                learning_rate=0.05,
                max_depth=15,
                min_samples_split=10,
                subsample=0.8,
                random_state=42,
                verbose=1
            ),
            'svm': SVC(
                C=1.0,
                kernel='rbf',
                gamma='scale',
                class_weight='balanced',
                probability=True,
                random_state=42,
                verbose=True
            ),
            'neural_network': MLPClassifier(
                hidden_layer_sizes=(512, 256, 128, 64),
                activation='relu',
                solver='adam',
                alpha=0.0001,
                batch_size=128,
                learning_rate='adaptive',
                max_iter=100,
                random_state=42,
                early_stopping=True,
                verbose=True
            )
        }
    
    def load_and_prepare_dataset(self, max_samples: int = 20000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Carga dataset profesional y extrae features
        """
        logger.info(f"Loading dataset from {self.dataset_path}")
        data = json.loads(self.dataset_path.read_text())
        
        # BALANCE: tomar mitad vulnerable, mitad safe
        all_samples = data['samples']
        vulnerable = [s for s in all_samples if s['vulnerable']]
        safe = [s for s in all_samples if not s['vulnerable']]
        
        # Tomar max_samples/2 de cada uno
        half = max_samples // 2
        samples = vulnerable[:half] + safe[:half]
        
        # Shuffle para mezclar
        import random
        random.seed(42)
        random.shuffle(samples)
        
        logger.info(f"Using {len(samples)} samples ({half} vulnerable + {half} safe)")
        
        # Extraer features
        X = []
        y = []
        
        logger.info("Extracting features from C/C++ code...")
        
        for i, sample in enumerate(samples):
            if i % 1000 == 0:
                logger.info(f"Processed {i}/{len(samples)} samples...")
            
            try:
                features = self.feature_extractor.extract_all_features(sample['code'])
                X.append(features)
                
                # Simplificar labels (vulnerable vs safe)
                label = 'VULNERABLE' if sample['vulnerable'] else 'SAFE'
                y.append(label)
            except Exception as e:
                logger.warning(f"Failed sample {i}: {e}")
        
        X = np.array(X)
        y = np.array(y)
        
        logger.info(f"✅ Final dataset shape: {X.shape}")
        logger.info(f"Label distribution:")
        unique, counts = np.unique(y, return_counts=True)
        for label, count in zip(unique, counts):
            logger.info(f"  {label}: {count} ({count/len(y)*100:.1f}%)")
        
        return X, y
    
    def train_and_evaluate(self, X: np.ndarray, y: np.ndarray):
        """
        Entrena y evalúa modelos
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
        
        best_model_name = None
        best_f1 = 0
        results = {}
        
        for model_name, model in self.models.items():
            logger.info(f"\n{'='*60}")
            logger.info(f"Training {model_name.upper()}")
            logger.info(f"{'='*60}")
            
            model.fit(X_train_scaled, y_train_encoded)
            
            y_pred = model.predict(X_test_scaled)
            
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
            
            # ROC-AUC
            try:
                y_proba = model.predict_proba(X_test_scaled)[:, 1]
                roc_auc = roc_auc_score(y_test_encoded, y_proba)
                logger.info(f"ROC-AUC: {roc_auc:.4f}")
            except:
                roc_auc = None
            
            cm = confusion_matrix(y_test_encoded, y_pred)
            logger.info(f"Confusion Matrix:\n{cm}")
            
            report = classification_report(
                y_test_encoded, y_pred,
                target_names=label_encoder.classes_,
                zero_division=0
            )
            logger.info(f"\n{report}")
            
            results[model_name] = {
                'accuracy': accuracy,
                'f1_score': f1,
                'cv_f1_mean': cv_scores.mean(),
                'cv_f1_std': cv_scores.std(),
                'roc_auc': roc_auc,
                'confusion_matrix': cm.tolist()
            }
            
            if f1 > best_f1:
                best_f1 = f1
                best_model_name = model_name
        
        logger.info(f"\n{'='*60}")
        logger.info(f"BEST MODEL: {best_model_name.upper()} (F1={best_f1:.4f})")
        logger.info(f"{'='*60}")
        
        best_model = self.models[best_model_name]
        
        # Guardar
        joblib.dump(best_model, self.models_dir / 'professional_vulnerability_detector.joblib')
        joblib.dump(scaler, self.models_dir / 'professional_scaler.joblib')
        joblib.dump(label_encoder, self.models_dir / 'professional_label_encoder.joblib')
        
        metadata = {
            'model_type': best_model_name,
            'trained_date': datetime.now().isoformat(),
            'dataset_size': len(X),
            'train_size': len(X_train),
            'test_size': len(X_test),
            'num_features': X.shape[1],
            'classes': label_encoder.classes_.tolist(),
            'data_source': 'DiverseVul + BigVul (Academic datasets)',
            'results': results
        }
        
        (self.models_dir / 'professional_model_metadata.json').write_text(json.dumps(metadata, indent=2))
        logger.info(f"✅ Models saved")


def main():
    logger.info("="*60)
    logger.info("TRAINING WITH PROFESSIONAL ACADEMIC DATASET")
    logger.info("45,830 samples from DiverseVul + BigVul")
    logger.info("="*60)
    
    dataset_path = Path('/app/data/professional_vulnerability_dataset.json')
    
    trainer = ProfessionalVulnerabilityTrainer(dataset_path)
    
    # Load and prepare (limitar a 20K para que termine más rápido)
    X, y = trainer.load_and_prepare_dataset(max_samples=20000)
    
    # Train
    trainer.train_and_evaluate(X, y)
    
    logger.info("\n✅ Training completed!")


if __name__ == '__main__':
    main()
