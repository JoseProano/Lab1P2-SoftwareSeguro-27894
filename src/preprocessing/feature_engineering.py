"""
Feature Engineering and Preprocessing - SEMMA Phase: MODIFY
Prepares data for machine learning models
"""

import pandas as pd
import numpy as np
from typing import Dict, Any, List, Tuple
from loguru import logger
import pymongo
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
import re
import joblib
from pathlib import Path


class FeatureEngineer:
    """Handles feature engineering and data preprocessing"""
    
    def __init__(self, mongo_uri: str, db_name: str, config: Dict[str, Any]):
        """
        Initialize Feature Engineer
        
        Args:
            mongo_uri: MongoDB connection string
            db_name: Database name
            config: Configuration dictionary
        """
        self.client = pymongo.MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.config = config
        
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.tfidf_vectorizer = None
        self.imputer = SimpleImputer(strategy='median')
        
        logger.info("Feature Engineer initialized")
    
    def load_and_prepare_data(self) -> pd.DataFrame:
        """
        Load data from MongoDB and perform initial preparation
        
        Returns:
            Prepared DataFrame
        """
        logger.info("Loading data for feature engineering...")
        
        # Load all vulnerability data
        cve_data = list(self.db.cve_data.find())
        nvd_data = list(self.db.nvd_vulnerabilities.find())
        github_data = list(self.db.github_advisories.find())
        
        dfs = []
        
        # Process CVE data
        if cve_data:
            df_cve = pd.DataFrame(cve_data)
            df_cve = self._standardize_cve_data(df_cve)
            dfs.append(df_cve)
        
        # Process NVD data
        if nvd_data:
            df_nvd = pd.DataFrame(nvd_data)
            df_nvd = self._standardize_nvd_data(df_nvd)
            dfs.append(df_nvd)
        
        # Process GitHub data
        if github_data:
            df_github = pd.DataFrame(github_data)
            df_github = self._standardize_github_data(df_github)
            dfs.append(df_github)
        
        # Combine all data
        if not dfs:
            logger.error("No data available for feature engineering")
            return pd.DataFrame()
        
        df = pd.concat(dfs, ignore_index=True)
        logger.info(f"Loaded {len(df)} total records")
        
        return df
    
    def _standardize_cve_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize CVE data format"""
        standardized = pd.DataFrame()
        
        standardized['vulnerability_id'] = df.get('cve_id', '')
        standardized['description'] = df.get('description', '')
        standardized['cvss_score'] = pd.to_numeric(df.get('cvss_score', 0), errors='coerce')
        standardized['severity'] = df.get('severity', 'UNKNOWN')
        standardized['cwes'] = df.get('cwes', [])
        standardized['published_date'] = pd.to_datetime(df.get('published_date', ''), errors='coerce')
        standardized['source'] = 'CVE'
        
        return standardized
    
    def _standardize_nvd_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize NVD data format"""
        standardized = pd.DataFrame()
        
        standardized['vulnerability_id'] = df.get('cve_id', '')
        standardized['description'] = df.get('description', '')
        standardized['cvss_score'] = pd.to_numeric(df.get('cvss_score', 0), errors='coerce')
        standardized['severity'] = df.get('severity', 'UNKNOWN')
        standardized['cwes'] = df.get('cwes', [])
        standardized['published_date'] = pd.to_datetime(df.get('published_date', ''), errors='coerce')
        standardized['source'] = 'NVD'
        
        return standardized
    
    def _standardize_github_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize GitHub advisory data format"""
        standardized = pd.DataFrame()
        
        standardized['vulnerability_id'] = df.get('ghsa_id', '')
        standardized['description'] = df.get('description', '').fillna('') + ' ' + df.get('summary', '').fillna('')
        standardized['cvss_score'] = pd.to_numeric(df.get('cvss_score', 0), errors='coerce')
        standardized['severity'] = df.get('severity', 'UNKNOWN')
        standardized['cwes'] = df.get('cwes', [])
        standardized['published_date'] = pd.to_datetime(df.get('published_at', ''), errors='coerce')
        standardized['source'] = 'GitHub'
        
        return standardized
    
    def create_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create engineered features from raw data
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with engineered features
        """
        logger.info("Creating engineered features...")
        
        df = df.copy()
        
        # Text-based features
        df = self._create_text_features(df)
        
        # Temporal features
        df = self._create_temporal_features(df)
        
        # CVSS-based features
        df = self._create_cvss_features(df)
        
        # CWE-based features
        df = self._create_cwe_features(df)
        
        # Severity encoding
        df = self._encode_severity(df)
        
        # Create target variable (binary: high risk or not)
        df = self._create_target_variable(df)
        
        logger.info(f"Feature engineering complete. Shape: {df.shape}")
        return df
    
    def _create_text_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create features from text descriptions"""
        logger.info("Creating text features...")
        
        # Description length
        df['desc_length'] = df['description'].fillna('').str.len()
        df['desc_word_count'] = df['description'].fillna('').str.split().str.len()
        
        # Check for security keywords
        security_keywords = [
            'injection', 'xss', 'csrf', 'buffer overflow', 'sql injection',
            'authentication', 'authorization', 'encryption', 'vulnerability',
            'exploit', 'remote code execution', 'privilege escalation',
            'denial of service', 'memory', 'overflow', 'leak'
        ]
        
        for keyword in security_keywords:
            col_name = f'has_{keyword.replace(" ", "_")}'
            df[col_name] = df['description'].fillna('').str.lower().str.contains(keyword, regex=False).astype(int)
        
        # Sentiment/urgency indicators
        urgent_words = ['critical', 'severe', 'dangerous', 'actively exploited', 'zero-day']
        df['urgency_score'] = df['description'].fillna('').str.lower().apply(
            lambda x: sum(1 for word in urgent_words if word in x)
        )
        
        return df
    
    def _create_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create temporal features"""
        logger.info("Creating temporal features...")
        
        # Convert to datetime if not already (remove timezone info)
        df['published_date'] = pd.to_datetime(df['published_date'], errors='coerce').dt.tz_localize(None)
        
        # Extract date components
        df['publish_year'] = df['published_date'].dt.year
        df['publish_month'] = df['published_date'].dt.month
        df['publish_quarter'] = df['published_date'].dt.quarter
        df['publish_day_of_week'] = df['published_date'].dt.dayofweek
        
        # Days since publication
        reference_date = pd.Timestamp.now().tz_localize(None)
        df['days_since_publication'] = (reference_date - df['published_date']).dt.days
        
        # Is recent (last 30 days)
        df['is_recent'] = (df['days_since_publication'] <= 30).astype(int)
        
        return df
    
    def _create_cvss_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create CVSS-based features"""
        logger.info("Creating CVSS features...")
        
        # CVSS score filled with median
        df['cvss_score'] = df['cvss_score'].fillna(df['cvss_score'].median())
        
        # CVSS categories
        df['cvss_category'] = pd.cut(
            df['cvss_score'],
            bins=[0, 3.9, 6.9, 8.9, 10],
            labels=['Low', 'Medium', 'High', 'Critical']
        )
        
        # Binary high risk indicator
        df['is_high_cvss'] = (df['cvss_score'] >= 7.0).astype(int)
        df['is_critical_cvss'] = (df['cvss_score'] >= 9.0).astype(int)
        
        # Squared CVSS (non-linear relationship)
        df['cvss_squared'] = df['cvss_score'] ** 2
        
        return df
    
    def _create_cwe_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create CWE-based features"""
        logger.info("Creating CWE features...")
        
        # Number of CWEs
        df['cwe_count'] = df['cwes'].apply(lambda x: len(x) if isinstance(x, list) else 0)
        
        # Has CWE
        df['has_cwe'] = (df['cwe_count'] > 0).astype(int)
        
        # Top dangerous CWEs (OWASP Top 10 related)
        dangerous_cwes = [
            'CWE-79',   # XSS
            'CWE-89',   # SQL Injection
            'CWE-20',   # Improper Input Validation
            'CWE-78',   # OS Command Injection
            'CWE-22',   # Path Traversal
            'CWE-352',  # CSRF
            'CWE-434',  # Unrestricted Upload
            'CWE-798',  # Hard-coded Credentials
            'CWE-94',   # Code Injection
            'CWE-287'   # Improper Authentication
        ]
        
        def has_dangerous_cwe(cwes):
            if not isinstance(cwes, list):
                return 0
            return int(any(cwe in dangerous_cwes for cwe in cwes))
        
        df['has_dangerous_cwe'] = df['cwes'].apply(has_dangerous_cwe)
        
        # CWE category features (one-hot encoding for top CWEs)
        all_cwes = []
        for cwes in df['cwes']:
            if isinstance(cwes, list):
                all_cwes.extend(cwes)
        
        if all_cwes:
            top_cwes = pd.Series(all_cwes).value_counts().head(20).index.tolist()
            
            for cwe in top_cwes:
                col_name = f'cwe_{cwe.replace("-", "_").lower()}'
                df[col_name] = df['cwes'].apply(
                    lambda x: int(cwe in x) if isinstance(x, list) else 0
                )
        
        return df
    
    def _encode_severity(self, df: pd.DataFrame) -> pd.DataFrame:
        """Encode severity levels"""
        logger.info("Encoding severity...")
        
        severity_mapping = {
            'LOW': 1,
            'MEDIUM': 2,
            'HIGH': 3,
            'CRITICAL': 4,
            'UNKNOWN': 0
        }
        
        df['severity_encoded'] = df['severity'].map(severity_mapping).fillna(0)
        
        return df
    
    def _create_target_variable(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create target variable for classification"""
        logger.info("Creating target variable...")
        
        # Define "vulnerable" as HIGH or CRITICAL severity OR CVSS >= 7.0
        df['is_vulnerable'] = (
            (df['severity'].isin(['HIGH', 'CRITICAL'])) |
            (df['cvss_score'] >= 7.0)
        ).astype(int)
        
        # Multi-class target (severity level)
        df['risk_level'] = df['severity'].map({
            'LOW': 0,
            'MEDIUM': 1,
            'HIGH': 2,
            'CRITICAL': 3,
            'UNKNOWN': 0
        }).fillna(0)
        
        return df
    
    def vectorize_text(self, df: pd.DataFrame, text_column: str = 'description') -> Tuple[np.ndarray, Any]:
        """
        Vectorize text using TF-IDF
        
        Args:
            df: DataFrame with text data
            text_column: Column name containing text
            
        Returns:
            Tuple of (vectorized features, vectorizer)
        """
        logger.info(f"Vectorizing text from '{text_column}'...")
        
        texts = df[text_column].fillna('').values
        
        if self.tfidf_vectorizer is None:
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=self.config.get('features', {}).get('text_features', {}).get('max_features', 5000),
                ngram_range=tuple(self.config.get('features', {}).get('text_features', {}).get('ngram_range', [1, 2])),
                min_df=2,
                max_df=0.95,
                stop_words='english'
            )
            text_features = self.tfidf_vectorizer.fit_transform(texts)
        else:
            text_features = self.tfidf_vectorizer.transform(texts)
        
        logger.info(f"Text vectorization complete. Shape: {text_features.shape}")
        return text_features, self.tfidf_vectorizer
    
    def prepare_for_modeling(
        self,
        df: pd.DataFrame,
        include_text_features: bool = True
    ) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Prepare final dataset for modeling
        
        Args:
            df: DataFrame with engineered features
            include_text_features: Whether to include TF-IDF text features
            
        Returns:
            Tuple of (X, y, feature_names)
        """
        logger.info("Preparing data for modeling...")
        
        # Select feature columns (exclude metadata and target)
        exclude_cols = [
            '_id', 'vulnerability_id', 'description', 'cwes', 'published_date',
            'source', 'severity', 'cvss_category', 'is_vulnerable', 'risk_level'
        ]
        
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        
        # Get numerical features
        X_numerical = df[feature_cols].select_dtypes(include=[np.number]).fillna(0).values
        numerical_feature_names = df[feature_cols].select_dtypes(include=[np.number]).columns.tolist()
        
        # Scale numerical features
        X_numerical_scaled = self.scaler.fit_transform(X_numerical)
        
        if include_text_features:
            # Add TF-IDF features
            X_text, _ = self.vectorize_text(df)
            X_text_dense = X_text.toarray()
            
            # Combine features
            X = np.hstack([X_numerical_scaled, X_text_dense])
            feature_names = numerical_feature_names + [f'tfidf_{i}' for i in range(X_text_dense.shape[1])]
        else:
            X = X_numerical_scaled
            feature_names = numerical_feature_names
        
        # Get target variable
        y = df['is_vulnerable'].values
        
        logger.info(f"Final dataset shape: X={X.shape}, y={y.shape}")
        logger.info(f"Class distribution: {pd.Series(y).value_counts().to_dict()}")
        
        return X, y, feature_names
    
    def split_data(
        self,
        X: np.ndarray,
        y: np.ndarray,
        test_size: float = 0.2,
        random_state: int = 42
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Split data into training and testing sets
        
        Args:
            X: Feature matrix
            y: Target vector
            test_size: Proportion of test set
            random_state: Random seed
            
        Returns:
            Tuple of (X_train, X_test, y_train, y_test)
        """
        logger.info(f"Splitting data (test_size={test_size})...")
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=test_size,
            random_state=random_state,
            stratify=y
        )
        
        logger.info(f"Training set: {X_train.shape}, Test set: {X_test.shape}")
        return X_train, X_test, y_train, y_test
    
    def save_preprocessors(self, output_dir: str = "./models"):
        """Save preprocessing objects for later use"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        joblib.dump(self.scaler, output_path / 'scaler.joblib')
        joblib.dump(self.tfidf_vectorizer, output_path / 'tfidf_vectorizer.joblib')
        joblib.dump(self.label_encoders, output_path / 'label_encoders.joblib')
        
        logger.info(f"Preprocessors saved to {output_dir}")
    
    def close(self):
        """Close database connection"""
        self.client.close()
        logger.info("Feature Engineer connection closed")


def main():
    """Main execution function"""
    import os
    import yaml
    from dotenv import load_dotenv
    
    load_dotenv()
    
    mongo_uri = f"mongodb://{os.getenv('MONGO_ROOT_USER')}:{os.getenv('MONGO_ROOT_PASSWORD')}@{os.getenv('MONGO_HOST', 'localhost')}:{os.getenv('MONGO_PORT', 27017)}/"
    db_name = os.getenv('MONGO_DB', 'vulnerability_db')
    
    # Load config
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
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
        np.save('data/X_train.npy', X_train)
        np.save('data/X_test.npy', X_test)
        np.save('data/y_train.npy', y_train)
        np.save('data/y_test.npy', y_test)
        
        logger.info("Feature engineering complete. Data saved to 'data/' directory")
        
    finally:
        engineer.close()


if __name__ == "__main__":
    main()
