"""
Production-Grade Vulnerability Detector Trainer
Basado en estrategias de BigVul, SARD, y research papers de AI for SAST

Features:
1. AST-based feature extraction (no solo TF-IDF)
2. Weighted loss para manejar desbalance
3. Control Flow Graph patterns
4. Real-world validation
"""
import json
import numpy as np
from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from loguru import logger
import re
from collections import Counter
from typing import Dict, List, Tuple


class ASTFeatureExtractor:
    """
    Extractor de features basado en AST y CFG
    Inspirado en Devign y CodeXGLUE
    """
    
    @staticmethod
    def extract_ast_features(code: str) -> np.ndarray:
        """
        Extrae features estructurales del código (AST-like sin parser completo)
        """
        features = []
        
        # 1. Longitud y complejidad
        features.append(len(code))
        features.append(len(code.split('\n')))
        features.append(len(code.split()))
        
        # 2. Control flow indicators
        control_keywords = ['if', 'else', 'for', 'while', 'switch', 'case', 'try', 'catch', 'finally']
        features.append(sum(code.lower().count(kw) for kw in control_keywords))
        
        # 3. Function/method calls (potential sinks)
        features.append(code.count('('))
        features.append(code.count('.'))
        
        # 4. String operations (común en injections)
        features.append(code.count('+'))  # Concatenation
        features.append(code.count('f"') + code.count("f'") + code.count('`'))  # String interpolation
        features.append(code.count('"') + code.count("'"))  # String literals
        
        # 5. SQL patterns (taint sources para CWE-89)
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'where', 'from']
        features.append(sum(code.lower().count(kw) for kw in sql_keywords))
        
        # 6. Command execution patterns (CWE-78)
        exec_patterns = ['exec', 'eval', 'system', 'popen', 'subprocess', 'runtime', 'processbuilder', 'shell']
        features.append(sum(code.lower().count(pat) for pat in exec_patterns))
        
        # 7. File operations (CWE-22)
        file_ops = ['open', 'file', 'read', 'write', 'path', 'sendfile', 'readfile']
        features.append(sum(code.lower().count(op) for op in file_ops))
        
        # 8. Crypto indicators (CWE-327)
        crypto_weak = ['md5', 'sha1', 'des', 'rc4']
        crypto_strong = ['sha256', 'sha512', 'bcrypt', 'argon2', 'aes256']
        features.append(sum(code.lower().count(w) for w in crypto_weak))
        features.append(sum(code.lower().count(s) for s in crypto_strong))
        
        # 9. Sanitization indicators (defensive code)
        sanitize_keywords = ['escape', 'sanitize', 'validate', 'filter', 'whitelist', 'prepare', 'parameterized']
        features.append(sum(code.lower().count(kw) for kw in sanitize_keywords))
        
        # 10. Hard-coded credentials patterns (CWE-798)
        hardcoded_patterns = [
            r'password\s*=\s*["\']',
            r'api[_-]?key\s*=\s*["\']',
            r'secret\s*=\s*["\']',
            r'token\s*=\s*["\'][a-zA-Z0-9]+',
        ]
        features.append(sum(bool(re.search(pat, code, re.IGNORECASE)) for pat in hardcoded_patterns))
        
        # 11. Input sources (taint sources)
        input_sources = ['request', 'input', 'argv', 'query', 'params', 'form', 'body', 'cookie', 'header']
        features.append(sum(code.lower().count(src) for src in input_sources))
        
        # 12. Dangerous sinks
        dangerous_sinks = ['innerhtml', 'eval', 'exec', 'system', 'query', 'execute']
        features.append(sum(code.lower().count(sink) for sink in dangerous_sinks))
        
        # 13. Type safety indicators
        type_keywords = ['int', 'str', 'bool', 'float', 'string', 'number', 'boolean']
        features.append(sum(code.lower().count(t) for t in type_keywords))
        
        # 14. Exception handling (good practice)
        features.append(code.lower().count('try'))
        features.append(code.lower().count('except') + code.lower().count('catch'))
        
        # 15. Environment variables (good practice vs hard-coded)
        env_patterns = ['getenv', 'process.env', 'os.environ', 'system.getenv']
        features.append(sum(code.lower().count(env) for env in env_patterns))
        
        # 16. Deserialization (CWE-502)
        deser_patterns = ['pickle', 'unserialize', 'deserialize', 'readobject', 'loads']
        features.append(sum(code.lower().count(d) for d in deser_patterns))
        
        # 17. XML processing (CWE-611)
        xml_patterns = ['xml', 'etree', 'documentbuilder', 'saxparser']
        features.append(sum(code.lower().count(x) for x in xml_patterns))
        
        # 18. Security annotations/decorators
        security_markers = ['@csrf', '@authorize', '@authenticate', '@secure', '@validated']
        features.append(sum(code.lower().count(m) for m in security_markers))
        
        # 19. Regular expressions (pueden indicar validación)
        features.append(code.count('re.') + code.count('regex') + code.count('/^'))
        
        # 20. Comments (código bien documentado suele ser más seguro)
        features.append(code.count('//') + code.count('#'))
        features.append(code.count('/*') + code.count('"""'))
        
        return np.array(features, dtype=np.float64)


class ProductionVulnerabilityTrainer:
    """
    Entrenador de modelos de producción para detección de vulnerabilidades
    """
    
    def __init__(self, data_file: str):
        self.data_file = Path(data_file)
        self.ast_extractor = ASTFeatureExtractor()
        
        # Modelos
        self.vulnerability_detector = None
        self.cwe_classifier = None
        
        # Feature processors
        self.tfidf_vectorizer = None
        self.scaler = None
        self.cwe_encoder = None
        
    def load_data(self) -> Tuple[List[str], List[bool], List[str]]:
        """Carga datos de entrenamiento"""
        logger.info(f"📂 Loading data from {self.data_file}")
        
        with open(self.data_file) as f:
            data = json.load(f)
        
        codes = [sample['code'] for sample in data]
        is_vulnerable = [sample['is_vulnerable'] for sample in data]
        cwe_ids = [sample.get('cwe_id', 'SAFE') for sample in data]
        
        logger.info(f"✅ Loaded {len(codes)} samples")
        
        # Stats
        vuln_count = sum(is_vulnerable)
        safe_count = len(is_vulnerable) - vuln_count
        logger.info(f"   Vulnerable: {vuln_count} ({vuln_count/len(codes)*100:.1f}%)")
        logger.info(f"   Safe: {safe_count} ({safe_count/len(codes)*100:.1f}%)")
        
        # CWE distribution
        cwe_counter = Counter(cwe_ids)
        logger.info("   CWE distribution:")
        for cwe, count in sorted(cwe_counter.items()):
            logger.info(f"      {cwe}: {count}")
        
        return codes, is_vulnerable, cwe_ids
    
    def extract_features(self, codes: List[str]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Extrae features híbridos: AST + TF-IDF
        Estrategia BigVul: Combinar features estructurales con semánticos
        """
        logger.info("🔧 Extracting hybrid features (AST + TF-IDF)...")
        
        # 1. AST-based features (30 features)
        ast_features = np.array([self.ast_extractor.extract_ast_features(code) for code in codes])
        logger.info(f"   AST features: {ast_features.shape}")
        
        # 2. TF-IDF features (character n-grams 2-5)
        if self.tfidf_vectorizer is None:
            self.tfidf_vectorizer = TfidfVectorizer(
                analyzer='char',
                ngram_range=(2, 5),
                max_features=5000,  # Reducido de 10K para evitar overfitting
                min_df=2,
                max_df=0.95
            )
            tfidf_features = self.tfidf_vectorizer.fit_transform(codes).toarray()
        else:
            tfidf_features = self.tfidf_vectorizer.transform(codes).toarray()
        
        logger.info(f"   TF-IDF features: {tfidf_features.shape}")
        
        # 3. Combinar
        combined_features = np.hstack([ast_features, tfidf_features])
        logger.info(f"   Combined features: {combined_features.shape}")
        
        # 4. Normalizar solo AST features (TF-IDF ya está normalizado)
        if self.scaler is None:
            self.scaler = StandardScaler()
            ast_scaled = self.scaler.fit_transform(ast_features)
        else:
            ast_scaled = self.scaler.transform(ast_features)
        
        final_features = np.hstack([ast_scaled, tfidf_features])
        
        return final_features, ast_features
    
    def train_vulnerability_detector(
        self,
        X: np.ndarray,
        y: np.ndarray
    ) -> GradientBoostingClassifier:
        """
        Entrena detector binario: Safe vs Vulnerable
        Usa weighted loss para manejar desbalance
        """
        logger.info("🎯 Training Binary Vulnerability Detector...")
        
        # Calcular class weights
        vuln_count = sum(y)
        safe_count = len(y) - vuln_count
        
        # Weight inversely proportional to frequency
        sample_weights = np.array([
            safe_count / len(y) if label else vuln_count / len(y)
            for label in y
        ])
        
        logger.info(f"   Class weights: Safe={vuln_count/len(y):.3f}, Vulnerable={safe_count/len(y):.3f}")
        
        # Split
        X_train, X_test, y_train, y_test, w_train, w_test = train_test_split(
            X, y, sample_weights, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train with weighted loss
        model = GradientBoostingClassifier(
            n_estimators=200,  # Reducido de 300 para evitar overfitting
            learning_rate=0.05,  # Menor learning rate = más generalización
            max_depth=5,  # Reducido de 7 para evitar overfitting
            min_samples_split=10,
            min_samples_leaf=5,
            subsample=0.8,
            random_state=42,
            verbose=1
        )
        
        logger.info("   Training with weighted samples...")
        model.fit(X_train, y_train, sample_weight=w_train)
        
        # Evaluate
        train_score = model.score(X_train, y_train)
        test_score = model.score(X_test, y_test)
        
        logger.info(f"   Training Accuracy: {train_score*100:.2f}%")
        logger.info(f"   Test Accuracy: {test_score*100:.2f}%")
        
        # Cross-validation
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(model, X, y, cv=cv, scoring='f1')
        logger.info(f"   Cross-Validation F1: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")
        
        # Classification report
        y_pred = model.predict(X_test)
        logger.info("\n" + classification_report(
            y_test, y_pred,
            target_names=['Safe', 'Vulnerable'],
            digits=3
        ))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        logger.info(f"   Confusion Matrix:\n{cm}")
        
        self.vulnerability_detector = model
        return model
    
    def train_cwe_classifier(
        self,
        X: np.ndarray,
        cwe_ids: List[str]
    ) -> RandomForestClassifier:
        """
        Entrena clasificador multi-clase de CWEs
        Solo en muestras vulnerables
        """
        logger.info("🎯 Training CWE Multi-Class Classifier...")
        
        # Filtrar solo vulnerables
        vuln_indices = [i for i, cwe in enumerate(cwe_ids) if cwe != 'SAFE']
        X_vuln = X[vuln_indices]
        cwe_vuln = [cwe_ids[i] for i in vuln_indices]
        
        logger.info(f"   Training on {len(X_vuln)} vulnerable samples")
        
        # Encode CWEs
        if self.cwe_encoder is None:
            self.cwe_encoder = LabelEncoder()
            y_encoded = self.cwe_encoder.fit_transform(cwe_vuln)
        else:
            y_encoded = self.cwe_encoder.transform(cwe_vuln)
        
        logger.info(f"   CWE classes: {list(self.cwe_encoder.classes_)}")
        
        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            X_vuln, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        # Train
        model = RandomForestClassifier(
            n_estimators=150,  # Reducido de 200
            max_depth=12,  # Reducido de 15
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',  # Weighted loss automático
            random_state=42,
            n_jobs=-1,
            verbose=1
        )
        
        logger.info("   Training CWE classifier...")
        model.fit(X_train, y_train)
        
        # Evaluate
        train_score = model.score(X_train, y_train)
        test_score = model.score(X_test, y_test)
        
        logger.info(f"   Training Accuracy: {train_score*100:.2f}%")
        logger.info(f"   Test Accuracy: {test_score*100:.2f}%")
        
        # Classification report
        y_pred = model.predict(X_test)
        logger.info("\n" + classification_report(
            y_test, y_pred,
            target_names=self.cwe_encoder.classes_,
            digits=3
        ))
        
        self.cwe_classifier = model
        return model
    
    def save_models(self, output_dir: str = './models'):
        """Guarda modelos y processors"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        logger.info(f"💾 Saving models to {output_path}")
        
        # Modelos
        joblib.dump(self.vulnerability_detector, output_path / 'production_vulnerability_detector.joblib')
        joblib.dump(self.cwe_classifier, output_path / 'production_cwe_classifier.joblib')
        
        # Processors
        joblib.dump(self.tfidf_vectorizer, output_path / 'production_vectorizer.joblib')
        joblib.dump(self.scaler, output_path / 'production_scaler.joblib')
        joblib.dump(self.cwe_encoder, output_path / 'production_cwe_encoder.joblib')
        
        logger.info("✅ Models saved successfully")
    
    def train_all(self):
        """Pipeline completo de entrenamiento"""
        logger.info("=" * 60)
        logger.info("🚀 Production Vulnerability Detector Training")
        logger.info("=" * 60)
        
        # 1. Load data
        codes, is_vulnerable, cwe_ids = self.load_data()
        
        # 2. Extract features
        X, ast_features = self.extract_features(codes)
        
        # 3. Train binary detector
        self.train_vulnerability_detector(X, np.array(is_vulnerable))
        
        # 4. Train CWE classifier
        self.train_cwe_classifier(X, cwe_ids)
        
        # 5. Save
        self.save_models()
        
        logger.info("=" * 60)
        logger.info("✅ Training Complete!")
        logger.info("=" * 60)


def main():
    """Main training pipeline"""
    trainer = ProductionVulnerabilityTrainer(
        data_file='./data/bigvul_training_data.json'
    )
    trainer.train_all()


if __name__ == '__main__':
    main()
