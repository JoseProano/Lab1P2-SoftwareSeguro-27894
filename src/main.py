"""
Main execution script for the vulnerability detection system
Orchestrates the complete SEMMA pipeline
"""

import argparse
import sys
from pathlib import Path
from loguru import logger
import yaml
from dotenv import load_dotenv
import os


def setup_logging():
    """Configure logging"""
    logger.add(
        "logs/vulnerability_detection.log",
        rotation="10 MB",
        retention="10 days",
        level="INFO"
    )


def run_data_collection(config):
    """Phase 1: SAMPLE - Data Collection"""
    logger.info("="*60)
    logger.info("PHASE 1: SAMPLE - Data Collection")
    logger.info("="*60)
    
    from src.data_collection.cve_collector import CVECollector
    from src.data_collection.nvd_collector import NVDCollector
    from src.data_collection.github_collector import GitHubAdvisoryCollector
    
    mongo_uri = f"mongodb://{os.getenv('MONGO_ROOT_USER')}:{os.getenv('MONGO_ROOT_PASSWORD')}@{os.getenv('MONGO_HOST', 'localhost')}:{os.getenv('MONGO_PORT', 27017)}/"
    db_name = os.getenv('MONGO_DB', 'vulnerability_db')
    
    # Collect CVE data
    logger.info("Collecting CVE data...")
    cve_collector = CVECollector(mongo_uri, db_name, "/app/cve_data")
    cve_count = cve_collector.collect_from_directory("2025")
    cve_collector.close()
    logger.info(f"Collected {cve_count} CVE records")
    
    # Collect NVD data
    logger.info("Collecting NVD data...")
    nvd_api_key = os.getenv('NVD_API_KEY')
    nvd_collector = NVDCollector(mongo_uri, db_name, nvd_api_key)
    nvd_count = nvd_collector.collect_recent_vulnerabilities(days=30)
    nvd_collector.close()
    logger.info(f"Collected {nvd_count} NVD records")
    
    # Collect GitHub advisories
    logger.info("Collecting GitHub advisories...")
    github_token = os.getenv('GITHUB_TOKEN')
    github_collector = GitHubAdvisoryCollector(mongo_uri, db_name, github_token)
    github_count = github_collector.collect_advisories(max_advisories=500)
    github_collector.close()
    logger.info(f"Collected {github_count} GitHub advisories")
    
    logger.info(f"Data collection complete. Total: {cve_count + nvd_count + github_count} records")


def run_exploration(config):
    """Phase 2: EXPLORE - Exploratory Data Analysis"""
    logger.info("="*60)
    logger.info("PHASE 2: EXPLORE - Exploratory Data Analysis")
    logger.info("="*60)
    
    from src.exploration.eda import VulnerabilityEDA
    
    mongo_uri = f"mongodb://{os.getenv('MONGO_ROOT_USER')}:{os.getenv('MONGO_ROOT_PASSWORD')}@{os.getenv('MONGO_HOST', 'localhost')}:{os.getenv('MONGO_PORT', 27017)}/"
    db_name = os.getenv('MONGO_DB', 'vulnerability_db')
    
    eda = VulnerabilityEDA(mongo_uri, db_name)
    
    try:
        df = eda.load_data()
        if not df.empty:
            report_path = eda.generate_report(df)
            logger.info(f"EDA report generated: {report_path}")
        else:
            logger.warning("No data available for exploration")
    finally:
        eda.close()


def run_preprocessing(config):
    """Phase 3: MODIFY - Data Preprocessing and Feature Engineering"""
    logger.info("="*60)
    logger.info("PHASE 3: MODIFY - Preprocessing & Feature Engineering")
    logger.info("="*60)
    
    from src.preprocessing.feature_engineering import FeatureEngineer
    import numpy as np
    
    mongo_uri = f"mongodb://{os.getenv('MONGO_ROOT_USER')}:{os.getenv('MONGO_ROOT_PASSWORD')}@{os.getenv('MONGO_HOST', 'localhost')}:{os.getenv('MONGO_PORT', 27017)}/"
    db_name = os.getenv('MONGO_DB', 'vulnerability_db')
    
    engineer = FeatureEngineer(mongo_uri, db_name, config)
    
    try:
        # Load and prepare data
        df = engineer.load_and_prepare_data()
        
        if df.empty:
            logger.error("No data to process")
            return
        
        # Create features
        df_features = engineer.create_features(df)
        
        # Prepare for modeling
        X, y, feature_names = engineer.prepare_for_modeling(df_features)
        
        # Split data
        X_train, X_test, y_train, y_test = engineer.split_data(X, y)
        
        # Save preprocessors
        engineer.save_preprocessors()
        
        # Save processed data
        Path('data').mkdir(exist_ok=True)
        np.save('data/X_train.npy', X_train)
        np.save('data/X_test.npy', X_test)
        np.save('data/y_train.npy', y_train)
        np.save('data/y_test.npy', y_test)
        
        logger.info(f"Preprocessing complete. Data shape: X={X.shape}, y={y.shape}")
        
    finally:
        engineer.close()


def run_modeling(config):
    """Phase 4: MODEL - Train Machine Learning Models"""
    logger.info("="*60)
    logger.info("PHASE 4: MODEL - Training ML Models")
    logger.info("="*60)
    
    from src.models.ml_models import VulnerabilityClassifier, VulnerabilityClusterer, AnomalyDetector
    import numpy as np
    
    # Load prepared data
    X_train = np.load('data/X_train.npy')
    X_test = np.load('data/X_test.npy')
    y_train = np.load('data/y_train.npy')
    y_test = np.load('data/y_test.npy')
    
    # Classification
    logger.info("Training classification models...")
    classifier = VulnerabilityClassifier(config)
    classifier.create_models()
    classifier.train_all_models(X_train, y_train)
    scores = classifier.evaluate_models(X_test, y_test)
    classifier.save_models()
    
    best_model_name, best_model = classifier.get_best_model()
    logger.info(f"Best classifier: {best_model_name}")
    
    # Clustering
    logger.info("Training clustering models...")
    clusterer = VulnerabilityClusterer(config)
    clusterer.create_models()
    cluster_labels = clusterer.fit_all_models(X_train)
    clusterer.save_models()
    
    # Anomaly Detection
    logger.info("Training anomaly detection models...")
    detector = AnomalyDetector(config)
    detector.create_models()
    anomaly_preds = detector.fit_all_models(X_train)
    detector.save_models()
    
    logger.info("Model training complete")


def run_assessment(config):
    """Phase 5: ASSESS - Model Evaluation and Interpretability"""
    logger.info("="*60)
    logger.info("PHASE 5: ASSESS - Model Evaluation")
    logger.info("="*60)
    
    from src.evaluation.model_evaluation import ModelEvaluator
    import numpy as np
    import joblib
    from pathlib import Path
    
    # Load data
    X_train = np.load('data/X_train.npy')
    X_test = np.load('data/X_test.npy')
    y_train = np.load('data/y_train.npy')
    y_test = np.load('data/y_test.npy')
    
    # Load models
    model_dir = Path('models')
    models = {}
    for model_file in model_dir.glob('*_classifier.joblib'):
        model_name = model_file.stem.replace('_classifier', '')
        models[model_name] = joblib.load(model_file)
    
    # Create evaluator
    evaluator = ModelEvaluator(config)
    
    # Evaluate all models
    for model_name, model in models.items():
        logger.info(f"Evaluating {model_name}...")
        results = evaluator.evaluate_model(
            model, model_name,
            X_train, X_test, y_train, y_test
        )
        evaluator.plot_confusion_matrix(model_name)
        
        if hasattr(model, 'feature_importances_'):
            evaluator.plot_feature_importance(model, model_name, None)
        
        # SHAP explanations for tree-based models
        if model_name in ['random_forest', 'decision_tree', 'xgboost', 'gradient_boosting']:
            evaluator.explain_with_shap(model, model_name, X_train, X_test)
    
    # Comparison plots
    evaluator.plot_roc_curve(models, X_test, y_test)
    evaluator.plot_precision_recall_curve(models, X_test, y_test)
    
    # Generate report
    report_path = evaluator.generate_assessment_report()
    logger.info(f"Assessment report: {report_path}")


def run_full_pipeline(config):
    """Run complete SEMMA pipeline"""
    logger.info("Starting full SEMMA pipeline...")
    
    try:
        run_data_collection(config)
        run_exploration(config)
        run_preprocessing(config)
        run_modeling(config)
        run_assessment(config)
        
        logger.info("="*60)
        logger.info("PIPELINE COMPLETE")
        logger.info("="*60)
        logger.info("Reports generated in ./reports directory")
        logger.info("Models saved in ./models directory")
        
    except Exception as e:
        logger.error(f"Pipeline error: {str(e)}")
        raise


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Vulnerability Detection System')
    parser.add_argument('--phase', choices=['sample', 'explore', 'modify', 'model', 'assess', 'all'],
                       default='all', help='SEMMA phase to execute')
    parser.add_argument('--config', type=str, default='config/config.yaml',
                       help='Configuration file path')
    
    args = parser.parse_args()
    
    # Setup
    load_dotenv()
    setup_logging()
    
    # Load configuration
    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)
    
    logger.info(f"Starting Vulnerability Detection System - Phase: {args.phase}")
    
    # Execute requested phase
    try:
        if args.phase == 'sample':
            run_data_collection(config)
        elif args.phase == 'explore':
            run_exploration(config)
        elif args.phase == 'modify':
            run_preprocessing(config)
        elif args.phase == 'model':
            run_modeling(config)
        elif args.phase == 'assess':
            run_assessment(config)
        elif args.phase == 'all':
            run_full_pipeline(config)
        
        logger.info("Execution completed successfully")
        
    except Exception as e:
        logger.error(f"Execution failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
