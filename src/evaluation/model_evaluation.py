"""
Model Evaluation and Interpretability - SEMMA Phase: ASSESS
Evaluates models and provides interpretability with SHAP
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, Any, List, Tuple
from loguru import logger
import joblib
from pathlib import Path
import json

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, precision_recall_curve, classification_report,
    confusion_matrix, cohen_kappa_score, matthews_corrcoef
)
from sklearn.model_selection import cross_val_score, cross_validate
import shap


class ModelEvaluator:
    """Comprehensive model evaluation and interpretability"""
    
    def __init__(self, config: Dict[str, Any], output_dir: str = "./reports"):
        """
        Initialize evaluator
        
        Args:
            config: Configuration dictionary
            output_dir: Directory for saving reports
        """
        self.config = config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.evaluation_results = {}
        
        logger.info(f"Model Evaluator initialized. Output: {output_dir}")
    
    def evaluate_model(
        self,
        model: Any,
        model_name: str,
        X_train: np.ndarray,
        X_test: np.ndarray,
        y_train: np.ndarray,
        y_test: np.ndarray,
        feature_names: List[str] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive model evaluation
        
        Args:
            model: Trained model
            model_name: Name of the model
            X_train: Training features
            X_test: Test features
            y_train: Training labels
            y_test: Test labels
            feature_names: Names of features
            
        Returns:
            Dictionary with evaluation results
        """
        logger.info(f"Evaluating {model_name}...")
        
        results = {}
        
        # Predictions
        y_pred = model.predict(X_test)
        
        # Probabilities (if available)
        if hasattr(model, 'predict_proba'):
            y_proba = model.predict_proba(X_test)[:, 1]
        else:
            y_proba = None
        
        # Basic metrics
        results['accuracy'] = accuracy_score(y_test, y_pred)
        results['precision'] = precision_score(y_test, y_pred, zero_division=0)
        results['recall'] = recall_score(y_test, y_pred, zero_division=0)
        results['f1_score'] = f1_score(y_test, y_pred, zero_division=0)
        results['kappa'] = cohen_kappa_score(y_test, y_pred)
        results['mcc'] = matthews_corrcoef(y_test, y_pred)
        
        if y_proba is not None:
            results['roc_auc'] = roc_auc_score(y_test, y_proba)
        
        # Cross-validation
        if self.config.get('semma', {}).get('assess', {}).get('cross_validation', {}).get('enabled', True):
            cv_folds = self.config.get('semma', {}).get('assess', {}).get('cross_validation', {}).get('folds', 5)
            cv_scores = cross_val_score(model, X_train, y_train, cv=cv_folds, scoring='f1')
            results['cv_f1_mean'] = cv_scores.mean()
            results['cv_f1_std'] = cv_scores.std()
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        results['confusion_matrix'] = cm.tolist()
        
        # Classification report
        report = classification_report(y_test, y_pred, output_dict=True)
        results['classification_report'] = report
        
        # Feature importance (if available)
        if hasattr(model, 'feature_importances_'):
            results['feature_importance'] = model.feature_importances_.tolist()
        
        self.evaluation_results[model_name] = results
        
        logger.info(f"{model_name} evaluation complete - F1: {results['f1_score']:.4f}")
        
        return results
    
    def plot_confusion_matrix(self, model_name: str):
        """Plot confusion matrix"""
        if model_name not in self.evaluation_results:
            logger.error(f"No evaluation results for {model_name}")
            return
        
        cm = np.array(self.evaluation_results[model_name]['confusion_matrix'])
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False)
        plt.title(f'Confusion Matrix - {model_name}', fontsize=14, fontweight='bold')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        
        plt.savefig(self.output_dir / f'{model_name}_confusion_matrix.png', dpi=300)
        plt.close()
        
        logger.info(f"Confusion matrix plot saved for {model_name}")
    
    def plot_roc_curve(
        self,
        models: Dict[str, Any],
        X_test: np.ndarray,
        y_test: np.ndarray
    ):
        """Plot ROC curves for multiple models"""
        plt.figure(figsize=(10, 8))
        
        for name, model in models.items():
            if hasattr(model, 'predict_proba'):
                y_proba = model.predict_proba(X_test)[:, 1]
                fpr, tpr, _ = roc_curve(y_test, y_proba)
                auc = roc_auc_score(y_test, y_proba)
                
                plt.plot(fpr, tpr, label=f'{name} (AUC = {auc:.3f})')
        
        plt.plot([0, 1], [0, 1], 'k--', label='Random')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curves - Model Comparison', fontsize=14, fontweight='bold')
        plt.legend()
        plt.grid(alpha=0.3)
        plt.tight_layout()
        
        plt.savefig(self.output_dir / 'roc_curves_comparison.png', dpi=300)
        plt.close()
        
        logger.info("ROC curves plot saved")
    
    def plot_precision_recall_curve(
        self,
        models: Dict[str, Any],
        X_test: np.ndarray,
        y_test: np.ndarray
    ):
        """Plot Precision-Recall curves"""
        plt.figure(figsize=(10, 8))
        
        for name, model in models.items():
            if hasattr(model, 'predict_proba'):
                y_proba = model.predict_proba(X_test)[:, 1]
                precision, recall, _ = precision_recall_curve(y_test, y_proba)
                
                plt.plot(recall, precision, label=name)
        
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curves', fontsize=14, fontweight='bold')
        plt.legend()
        plt.grid(alpha=0.3)
        plt.tight_layout()
        
        plt.savefig(self.output_dir / 'precision_recall_curves.png', dpi=300)
        plt.close()
        
        logger.info("Precision-Recall curves plot saved")
    
    def plot_feature_importance(
        self,
        model: Any,
        model_name: str,
        feature_names: List[str],
        top_n: int = 20
    ):
        """Plot feature importance"""
        if not hasattr(model, 'feature_importances_'):
            logger.warning(f"{model_name} does not have feature importances")
            return
        
        importances = model.feature_importances_
        
        # Get top N features
        indices = np.argsort(importances)[-top_n:]
        
        if feature_names:
            features = [feature_names[i] if i < len(feature_names) else f'Feature_{i}' for i in indices]
        else:
            features = [f'Feature_{i}' for i in indices]
        
        plt.figure(figsize=(10, 8))
        plt.barh(range(top_n), importances[indices])
        plt.yticks(range(top_n), features)
        plt.xlabel('Importance')
        plt.title(f'Top {top_n} Feature Importances - {model_name}', fontsize=14, fontweight='bold')
        plt.tight_layout()
        
        plt.savefig(self.output_dir / f'{model_name}_feature_importance.png', dpi=300)
        plt.close()
        
        logger.info(f"Feature importance plot saved for {model_name}")
    
    def explain_with_shap(
        self,
        model: Any,
        model_name: str,
        X_train: np.ndarray,
        X_test: np.ndarray,
        feature_names: List[str] = None,
        max_samples: int = 100
    ):
        """
        Generate SHAP explanations
        
        Args:
            model: Trained model
            model_name: Name of the model
            X_train: Training data (for background)
            X_test: Test data (to explain)
            feature_names: Feature names
            max_samples: Maximum samples for SHAP
        """
        logger.info(f"Generating SHAP explanations for {model_name}...")
        
        try:
            # Sample data for efficiency
            X_train_sample = X_train[:min(100, len(X_train))]
            X_test_sample = X_test[:min(max_samples, len(X_test))]
            
            # Create explainer - use TreeExplainer for tree models, KernelExplainer for others
            if hasattr(model, 'predict_proba'):
                # Try TreeExplainer first for tree-based models
                try:
                    explainer = shap.TreeExplainer(model)
                    shap_values = explainer.shap_values(X_test_sample)
                    
                    # Handle different output formats
                    if isinstance(shap_values, list):
                        shap_values_plot = shap_values[1]  # Positive class
                    else:
                        shap_values_plot = shap_values
                except:
                    # Fallback to sampling explainer with increased budget
                    explainer = shap.KernelExplainer(model.predict_proba, shap.sample(X_train_sample, 50))
                    shap_values = explainer.shap_values(X_test_sample, nsamples=100)
                    if isinstance(shap_values, list):
                        shap_values_plot = shap_values[1]
                    else:
                        shap_values_plot = shap_values
            else:
                explainer = shap.KernelExplainer(model.predict, shap.sample(X_train_sample, 50))
                shap_values_plot = explainer.shap_values(X_test_sample, nsamples=100)
            
            # Summary plot
            plt.figure(figsize=(10, 8))
            shap.summary_plot(
                shap_values_plot,
                X_test_sample,
                feature_names=feature_names[:X_test_sample.shape[1]] if feature_names else None,
                show=False,
                max_display=20
            )
            plt.tight_layout()
            plt.savefig(self.output_dir / f'{model_name}_shap_summary.png', dpi=300, bbox_inches='tight')
            plt.close()
            
            # Bar plot
            plt.figure(figsize=(10, 8))
            shap.summary_plot(
                shap_values_plot,
                X_test_sample,
                feature_names=feature_names[:X_test_sample.shape[1]] if feature_names else None,
                plot_type='bar',
                show=False,
                max_display=20
            )
            plt.tight_layout()
            plt.savefig(self.output_dir / f'{model_name}_shap_bar.png', dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"SHAP explanations generated for {model_name}")
            
        except Exception as e:
            logger.error(f"Error generating SHAP explanations for {model_name}: {str(e)}")
    
    def compare_models(self) -> pd.DataFrame:
        """Compare all evaluated models"""
        if not self.evaluation_results:
            logger.error("No models evaluated yet")
            return pd.DataFrame()
        
        comparison_data = []
        
        for model_name, results in self.evaluation_results.items():
            comparison_data.append({
                'Model': model_name,
                'Accuracy': results.get('accuracy', 0),
                'Precision': results.get('precision', 0),
                'Recall': results.get('recall', 0),
                'F1-Score': results.get('f1_score', 0),
                'ROC-AUC': results.get('roc_auc', 0),
                'Kappa': results.get('kappa', 0),
                'MCC': results.get('mcc', 0)
            })
        
        df_comparison = pd.DataFrame(comparison_data)
        df_comparison = df_comparison.sort_values('F1-Score', ascending=False)
        
        # Save comparison table
        df_comparison.to_csv(self.output_dir / 'model_comparison.csv', index=False)
        
        # Plot comparison
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        df_plot = df_comparison.set_index('Model')[metrics]
        
        ax = df_plot.plot(kind='bar', figsize=(12, 6), rot=45)
        ax.set_title('Model Performance Comparison', fontsize=14, fontweight='bold')
        ax.set_ylabel('Score')
        ax.set_ylim(0, 1)
        ax.legend(loc='lower right')
        plt.tight_layout()
        plt.savefig(self.output_dir / 'model_comparison.png', dpi=300)
        plt.close()
        
        logger.info("Model comparison complete")
        
        return df_comparison
    
    def generate_assessment_report(self) -> str:
        """Generate comprehensive assessment report"""
        logger.info("Generating assessment report...")
        
        comparison_df = self.compare_models()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Model Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
                h2 {{ color: #34495e; margin-top: 30px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #3498db; color: white; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .best {{ background-color: #2ecc71; color: white; font-weight: bold; }}
                .metric-card {{ display: inline-block; background: #ecf0f1; padding: 15px; margin: 10px; border-radius: 5px; min-width: 200px; }}
                .visualization {{ margin: 30px 0; text-align: center; }}
                .visualization img {{ max-width: 100%; border: 1px solid #ddd; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎯 Model Assessment Report (ASSESS Phase)</h1>
                <p><strong>Generated:</strong> {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>📊 Model Performance Comparison</h2>
                <table>
                    <tr>
                        <th>Model</th>
                        <th>Accuracy</th>
                        <th>Precision</th>
                        <th>Recall</th>
                        <th>F1-Score</th>
                        <th>ROC-AUC</th>
                    </tr>
        """
        
        for idx, row in comparison_df.iterrows():
            is_best = idx == 0
            row_class = ' class="best"' if is_best else ''
            html += f"""
                    <tr{row_class}>
                        <td>{row['Model']}</td>
                        <td>{row['Accuracy']:.4f}</td>
                        <td>{row['Precision']:.4f}</td>
                        <td>{row['Recall']:.4f}</td>
                        <td>{row['F1-Score']:.4f}</td>
                        <td>{row.get('ROC-AUC', 0):.4f}</td>
                    </tr>
            """
        
        best_model = comparison_df.iloc[0]['Model']
        
        html += f"""
                </table>
                
                <h2>🏆 Best Model: {best_model}</h2>
                
                <div class="visualization">
                    <h3>Model Comparison Chart</h3>
                    <img src="model_comparison.png" alt="Model Comparison">
                </div>
                
                <div class="visualization">
                    <h3>ROC Curves</h3>
                    <img src="roc_curves_comparison.png" alt="ROC Curves">
                </div>
                
                <div class="visualization">
                    <h3>Precision-Recall Curves</h3>
                    <img src="precision_recall_curves.png" alt="Precision-Recall">
                </div>
                
                <h2>🔍 Model Interpretability (SHAP)</h2>
        """
        
        # Add SHAP plots for each model
        for model_name in self.evaluation_results.keys():
            shap_summary = self.output_dir / f'{model_name}_shap_summary.png'
            if shap_summary.exists():
                html += f"""
                <div class="visualization">
                    <h3>{model_name} - SHAP Feature Importance</h3>
                    <img src="{model_name}_shap_summary.png" alt="{model_name} SHAP">
                </div>
                """
        
        html += """
            </div>
        </body>
        </html>
        """
        
        report_path = self.output_dir / 'assessment_report.html'
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        # Save results as JSON
        results_file = self.output_dir / 'evaluation_results.json'
        with open(results_file, 'w') as f:
            json.dump(self.evaluation_results, f, indent=2, default=str)
        
        logger.info(f"Assessment report generated: {report_path}")
        return str(report_path)


def main():
    """Main execution function"""
    import os
    import yaml
    from dotenv import load_dotenv
    
    load_dotenv()
    
    # Load config
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
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
    logger.info(f"Assessment complete. Report: {report_path}")


if __name__ == "__main__":
    main()
