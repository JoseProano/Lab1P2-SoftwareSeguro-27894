"""
ML Models - SEMMA Phase: MODEL
Implements classification, clustering, and anomaly detection models
"""

import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
from loguru import logger
import joblib
from pathlib import Path

# Classification models
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier

# Clustering models
from sklearn.cluster import KMeans, AgglomerativeClustering, DBSCAN
from sklearn.decomposition import PCA

# Anomaly detection
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.covariance import EllipticEnvelope

# Model selection and evaluation
from sklearn.model_selection import cross_val_score, GridSearchCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, classification_report, confusion_matrix
)

import warnings
warnings.filterwarnings('ignore')


class VulnerabilityClassifier:
    """Classification models for vulnerability prediction"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize classifier
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.models = {}
        self.best_model = None
        self.model_scores = {}
        
        logger.info("Vulnerability Classifier initialized")
    
    def create_models(self) -> Dict[str, Any]:
        """
        Create all classification models
        
        Returns:
            Dictionary of model instances
        """
        logger.info("Creating classification models...")
        
        rf_config = self.config.get('semma', {}).get('model', {}).get('random_forest', {})
        svm_config = self.config.get('semma', {}).get('model', {}).get('svm', {})
        dt_config = self.config.get('semma', {}).get('model', {}).get('decision_tree', {})
        xgb_config = self.config.get('semma', {}).get('model', {}).get('xgboost', {})
        
        self.models = {
            'random_forest': RandomForestClassifier(
                n_estimators=rf_config.get('n_estimators', 200),
                max_depth=rf_config.get('max_depth', 20),
                min_samples_split=rf_config.get('min_samples_split', 5),
                min_samples_leaf=rf_config.get('min_samples_leaf', 2),
                n_jobs=-1,
                random_state=42,
                class_weight='balanced'
            ),
            'decision_tree': DecisionTreeClassifier(
                max_depth=dt_config.get('max_depth', 15),
                min_samples_split=dt_config.get('min_samples_split', 10),
                random_state=42,
                class_weight='balanced'
            ),
            'svm': SVC(
                kernel=svm_config.get('kernel', 'rbf'),
                C=svm_config.get('C', 1.0),
                gamma=svm_config.get('gamma', 'scale'),
                probability=True,
                random_state=42,
                class_weight='balanced'
            ),
            'xgboost': XGBClassifier(
                n_estimators=xgb_config.get('n_estimators', 150),
                max_depth=xgb_config.get('max_depth', 10),
                learning_rate=xgb_config.get('learning_rate', 0.1),
                random_state=42,
                eval_metric='logloss',
                use_label_encoder=False
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            ),
            'mlp': MLPClassifier(
                hidden_layer_sizes=(128, 64, 32),
                activation='relu',
                max_iter=500,
                random_state=42,
                early_stopping=True
            )
        }
        
        logger.info(f"Created {len(self.models)} classification models")
        return self.models
    
    def train_all_models(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray
    ) -> Dict[str, Any]:
        """
        Train all classification models
        
        Args:
            X_train: Training features
            y_train: Training labels
            
        Returns:
            Dictionary of trained models
        """
        logger.info("Training all classification models...")
        
        for name, model in self.models.items():
            logger.info(f"Training {name}...")
            try:
                model.fit(X_train, y_train)
                logger.info(f"✓ {name} trained successfully")
            except Exception as e:
                logger.error(f"✗ Error training {name}: {str(e)}")
        
        logger.info("All models trained")
        return self.models
    
    def evaluate_models(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray
    ) -> Dict[str, Dict[str, float]]:
        """
        Evaluate all models
        
        Args:
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dictionary of model scores
        """
        logger.info("Evaluating all models...")
        
        for name, model in self.models.items():
            logger.info(f"Evaluating {name}...")
            
            try:
                y_pred = model.predict(X_test)
                y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
                
                scores = {
                    'accuracy': accuracy_score(y_test, y_pred),
                    'precision': precision_score(y_test, y_pred, zero_division=0),
                    'recall': recall_score(y_test, y_pred, zero_division=0),
                    'f1_score': f1_score(y_test, y_pred, zero_division=0)
                }
                
                if y_proba is not None:
                    scores['roc_auc'] = roc_auc_score(y_test, y_proba)
                
                self.model_scores[name] = scores
                
                logger.info(f"{name} - Accuracy: {scores['accuracy']:.4f}, F1: {scores['f1_score']:.4f}")
                
            except Exception as e:
                logger.error(f"Error evaluating {name}: {str(e)}")
        
        # Find best model
        self.best_model = max(self.model_scores.items(), key=lambda x: x[1]['f1_score'])[0]
        logger.info(f"Best model: {self.best_model}")
        
        return self.model_scores
    
    def get_best_model(self) -> Tuple[str, Any]:
        """
        Get best performing model
        
        Returns:
            Tuple of (model_name, model_instance)
        """
        if not self.best_model:
            logger.error("Models not evaluated yet")
            return None, None
        
        return self.best_model, self.models[self.best_model]
    
    def save_models(self, output_dir: str = "./models"):
        """Save all trained models"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for name, model in self.models.items():
            model_file = output_path / f'{name}_classifier.joblib'
            joblib.dump(model, model_file)
            logger.info(f"Saved {name} to {model_file}")
        
        # Save scores
        scores_file = output_path / 'model_scores.joblib'
        joblib.dump(self.model_scores, scores_file)
        
        logger.info(f"All models saved to {output_dir}")


class VulnerabilityClusterer:
    """Clustering models for vulnerability grouping"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize clusterer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.models = {}
        self.cluster_labels = {}
        
        logger.info("Vulnerability Clusterer initialized")
    
    def create_models(self) -> Dict[str, Any]:
        """Create clustering models"""
        logger.info("Creating clustering models...")
        
        kmeans_config = self.config.get('semma', {}).get('model', {}).get('kmeans', {})
        
        self.models = {
            'kmeans': KMeans(
                n_clusters=kmeans_config.get('n_clusters', 5),
                max_iter=kmeans_config.get('max_iter', 300),
                n_init=10,
                random_state=42
            ),
            'hierarchical': AgglomerativeClustering(
                n_clusters=5,
                linkage='ward'
            ),
            'dbscan': DBSCAN(
                eps=0.5,
                min_samples=5
            )
        }
        
        logger.info(f"Created {len(self.models)} clustering models")
        return self.models
    
    def fit_all_models(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Fit all clustering models
        
        Args:
            X: Feature matrix
            
        Returns:
            Dictionary of cluster labels
        """
        logger.info("Fitting clustering models...")
        
        # Reduce dimensionality for better clustering
        pca = PCA(n_components=50, random_state=42)
        X_reduced = pca.fit_transform(X)
        
        for name, model in self.models.items():
            logger.info(f"Fitting {name}...")
            try:
                labels = model.fit_predict(X_reduced)
                self.cluster_labels[name] = labels
                
                n_clusters = len(np.unique(labels))
                logger.info(f"✓ {name} - Found {n_clusters} clusters")
                
            except Exception as e:
                logger.error(f"✗ Error fitting {name}: {str(e)}")
        
        return self.cluster_labels
    
    def save_models(self, output_dir: str = "./models"):
        """Save clustering models"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for name, model in self.models.items():
            if hasattr(model, 'cluster_centers_'):  # KMeans
                model_file = output_path / f'{name}_clusterer.joblib'
                joblib.dump(model, model_file)
                logger.info(f"Saved {name} to {model_file}")


class AnomalyDetector:
    """Anomaly detection models"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize anomaly detector
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.models = {}
        self.anomaly_scores = {}
        
        logger.info("Anomaly Detector initialized")
    
    def create_models(self) -> Dict[str, Any]:
        """Create anomaly detection models"""
        logger.info("Creating anomaly detection models...")
        
        iso_config = self.config.get('semma', {}).get('model', {}).get('isolation_forest', {})
        
        # NOTE: Elliptic Envelope removed - too slow for large datasets (30K+ samples)
        # Only using Isolation Forest and One-Class SVM for anomaly detection
        self.models = {
            'isolation_forest': IsolationForest(
                contamination=iso_config.get('contamination', 0.1),
                max_samples=iso_config.get('max_samples', 'auto'),
                random_state=42,
                n_jobs=-1
            ),
            'one_class_svm': OneClassSVM(
                kernel='rbf',
                gamma='auto',
                nu=0.1
            )
        }
        
        logger.info(f"Created {len(self.models)} anomaly detection models")
        return self.models
    
    def fit_all_models(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Fit all anomaly detection models
        
        Args:
            X: Feature matrix (normal samples)
            
        Returns:
            Dictionary of anomaly predictions
        """
        logger.info("Fitting anomaly detection models...")
        
        predictions = {}
        
        for name, model in self.models.items():
            logger.info(f"Fitting {name}...")
            try:
                model.fit(X)
                preds = model.predict(X)
                
                # Convert to binary (1 = normal, -1 = anomaly)
                n_anomalies = np.sum(preds == -1)
                pct_anomalies = (n_anomalies / len(preds)) * 100
                
                predictions[name] = preds
                self.anomaly_scores[name] = {
                    'n_anomalies': int(n_anomalies),
                    'pct_anomalies': float(pct_anomalies)
                }
                
                logger.info(f"✓ {name} - Detected {n_anomalies} anomalies ({pct_anomalies:.2f}%)")
                
            except Exception as e:
                logger.error(f"✗ Error fitting {name}: {str(e)}")
        
        return predictions
    
    def save_models(self, output_dir: str = "./models"):
        """Save anomaly detection models"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for name, model in self.models.items():
            model_file = output_path / f'{name}_detector.joblib'
            joblib.dump(model, model_file)
            logger.info(f"Saved {name} to {model_file}")


def main():
    """Main execution function"""
    import os
    import yaml
    from dotenv import load_dotenv
    
    load_dotenv()
    
    # Load config
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Load prepared data
    logger.info("Loading prepared data...")
    X_train = np.load('data/X_train.npy')
    X_test = np.load('data/X_test.npy')
    y_train = np.load('data/y_train.npy')
    y_test = np.load('data/y_test.npy')
    
    # Classification
    logger.info("\n" + "="*60)
    logger.info("CLASSIFICATION MODELS")
    logger.info("="*60)
    
    classifier = VulnerabilityClassifier(config)
    classifier.create_models()
    classifier.train_all_models(X_train, y_train)
    scores = classifier.evaluate_models(X_test, y_test)
    classifier.save_models()
    
    # Clustering
    logger.info("\n" + "="*60)
    logger.info("CLUSTERING MODELS")
    logger.info("="*60)
    
    clusterer = VulnerabilityClusterer(config)
    clusterer.create_models()
    cluster_labels = clusterer.fit_all_models(X_train)
    clusterer.save_models()
    
    # Anomaly Detection
    logger.info("\n" + "="*60)
    logger.info("ANOMALY DETECTION MODELS")
    logger.info("="*60)
    
    detector = AnomalyDetector(config)
    detector.create_models()
    anomaly_preds = detector.fit_all_models(X_train)
    detector.save_models()
    
    logger.info("\n" + "="*60)
    logger.info("MODEL TRAINING COMPLETE")
    logger.info("="*60)
    
    # Print summary
    logger.info("\nClassification Results:")
    for model_name, model_scores in scores.items():
        logger.info(f"\n{model_name.upper()}:")
        for metric, value in model_scores.items():
            logger.info(f"  {metric}: {value:.4f}")


if __name__ == "__main__":
    main()
