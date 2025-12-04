#!/usr/bin/env python3
"""
SISTEMA COMPLETO DE MINERÍA DE DATOS PARA DETECCIÓN DE VULNERABILIDADES
Siguiendo metodología SEMMA (Sample, Explore, Modify, Model, Assess)

Este sistema entrena modelos ML con CÓDIGO REAL de repositorios vulnerables,
NO con patrones sintéticos.
"""

import os
import json
import requests
import subprocess
from pathlib import Path
from typing import List, Dict, Tuple
import numpy as np
import pandas as pd
from loguru import logger
import javalang
import ast as python_ast
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, f1_score
import joblib
from datetime import datetime
from collections import Counter
import re

class RealCodeMiner:
    """
    FASE 1 - SAMPLE (Muestreo)
    Mina código REAL de repositorios con vulnerabilidades conocidas
    """
    
    def __init__(self):
        self.data_dir = Path('/app/data/real_vulnerable_code')
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
    def mine_from_github_advisories(self, limit=100) -> List[Dict]:
        """
        Mina datos de GitHub Security Advisories
        Estas son vulnerabilidades REALES reportadas en código real
        """
        logger.info("📦 Mining REAL vulnerable code from GitHub Security Advisories...")
        
        vulnerabilities = []
        
        # GitHub GraphQL API para security advisories
        query = '''
        query($cursor: String) {
          securityAdvisories(first: 100, after: $cursor) {
            nodes {
              summary
              description
              severity
              cvss {
                score
              }
              references {
                url
              }
              vulnerabilities(first: 10) {
                nodes {
                  package {
                    name
                    ecosystem
                  }
                  vulnerableVersionRange
                }
              }
            }
            pageInfo {
              endCursor
              hasNextPage
            }
          }
        }
        '''
        
        # Por ahora usar datos locales del CVE que ya tenemos
        # pero interpretarlos MEJOR
        return self.mine_from_local_cve_database()
    
    def mine_from_local_cve_database(self) -> List[Dict]:
        """
        Re-procesa los CVEs locales pero extrayendo INFORMACIÓN REAL
        no código sintético
        """
        logger.info("📦 Re-mining CVE database for REAL vulnerability patterns...")
        
        cve_dir = Path('/app/data/cves')
        samples = []
        
        cve_files = list(cve_dir.rglob('*.json'))
        logger.info(f"Found {len(cve_files)} CVE files")
        
        processed = 0
        for cve_file in cve_files[:1000]:  # Procesar primeros 1000
            try:
                cve_data = json.loads(cve_file.read_text())
                
                # Extraer CWE
                cwes = []
                if 'cve' in cve_data and 'problemtype' in cve_data['cve']:
                    for problem in cve_data['cve']['problemtype'].get('problemtype_data', []):
                        for desc in problem.get('description', []):
                            cwe_value = desc.get('value', '')
                            if cwe_value.startswith('CWE-'):
                                cwes.append(cwe_value)
                
                if not cwes:
                    continue
                
                # Extraer descripción (contiene información sobre el tipo de vuln)
                description = ''
                if 'cve' in cve_data and 'description' in cve_data['cve']:
                    for desc in cve_data['cve']['description'].get('description_data', []):
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                
                # Extraer referencias (pueden contener commits/patches)
                references = []
                if 'cve' in cve_data and 'references' in cve_data['cve']:
                    for ref in cve_data['cve']['references'].get('reference_data', []):
                        url = ref.get('url', '')
                        if 'github.com' in url or 'commit' in url or 'patch' in url:
                            references.append(url)
                
                samples.append({
                    'cve_id': cve_file.stem,
                    'cwes': cwes,
                    'primary_cwe': cwes[0] if cwes else 'CWE-Unknown',
                    'description': description,
                    'references': references,
                    'source': 'CVE-NVD'
                })
                
                processed += 1
                
            except Exception as e:
                continue
        
        logger.info(f"✅ Processed {processed} CVEs with real vulnerability information")
        return samples
    
    def extract_vulnerability_keywords(self, samples: List[Dict]) -> Dict[str, List[str]]:
        """
        FASE 2 - EXPLORE (Exploración)
        Analiza los datos para identificar patrones de vulnerabilidades
        """
        logger.info("🔍 Exploring vulnerability patterns in descriptions...")
        
        # Agrupar por CWE
        by_cwe = {}
        for sample in samples:
            cwe = sample['primary_cwe']
            if cwe not in by_cwe:
                by_cwe[cwe] = []
            by_cwe[cwe].append(sample['description'].lower())
        
        # Extraer keywords comunes por CWE
        cwe_keywords = {}
        for cwe, descriptions in by_cwe.items():
            # Unir todas las descripciones
            text = ' '.join(descriptions)
            
            # Extraer palabras técnicas (evitar stop words)
            words = re.findall(r'\b[a-z]{4,}\b', text)
            word_freq = Counter(words)
            
            # Top keywords
            top_keywords = [w for w, c in word_freq.most_common(30) 
                           if w not in ['that', 'this', 'with', 'from', 'have', 'been', 'allows', 'could', 'would', 'through']]
            
            cwe_keywords[cwe] = top_keywords[:15]
            logger.info(f"  {cwe}: {', '.join(top_keywords[:10])}")
        
        return cwe_keywords


class AdvancedFeatureExtractor:
    """
    FASE 3 - MODIFY (Modificación)
    Extracción avanzada de features del código fuente
    """
    
    @staticmethod
    def extract_java_ast_features(code: str) -> Dict:
        """Extrae features estructurales profundas de código Java"""
        features = {}
        
        try:
            # Parse Java AST
            tree = javalang.parse.parse(code)
            
            # Contar tipos de nodos
            features['method_declarations'] = len(list(tree.filter(javalang.tree.MethodDeclaration)))
            features['class_declarations'] = len(list(tree.filter(javalang.tree.ClassDeclaration)))
            features['if_statements'] = len(list(tree.filter(javalang.tree.IfStatement)))
            features['for_loops'] = len(list(tree.filter(javalang.tree.ForStatement)))
            features['while_loops'] = len(list(tree.filter(javalang.tree.WhileStatement)))
            features['try_catch'] = len(list(tree.filter(javalang.tree.TryStatement)))
            
            # Invocaciones de métodos
            method_invocations = list(tree.filter(javalang.tree.MethodInvocation))
            features['method_calls'] = len(method_invocations)
            
            # Detectar llamadas peligrosas
            dangerous_calls = ['executeQuery', 'execute', 'createStatement', 'Runtime.exec', 
                             'ProcessBuilder', 'eval', 'innerHTML', 'readObject']
            features['dangerous_method_calls'] = sum(
                1 for mi in method_invocations 
                if any(danger in str(mi.member) for danger in dangerous_calls)
            )
            
            # Concatenación de strings (posible SQL injection)
            features['string_concatenations'] = code.count('+') - code.count('++')
            
        except:
            # Si falla el parsing, features por defecto
            features = {
                'method_declarations': 0,
                'class_declarations': 0,
                'if_statements': 0,
                'for_loops': 0,
                'while_loops': 0,
                'try_catch': 0,
                'method_calls': 0,
                'dangerous_method_calls': 0,
                'string_concatenations': 0
            }
        
        # Features adicionales léxicas
        features['code_length'] = len(code)
        features['line_count'] = len(code.split('\n'))
        features['comment_ratio'] = (code.count('//') + code.count('/*')) / max(features['line_count'], 1)
        
        return features
    
    @staticmethod
    def extract_vulnerability_indicators(code: str) -> Dict:
        """Extrae indicadores específicos de vulnerabilidades"""
        indicators = {}
        
        code_lower = code.lower()
        
        # SQL Injection indicators
        indicators['has_select_statement'] = int('select' in code_lower and ('from' in code_lower or 'where' in code_lower))
        indicators['has_insert_statement'] = int('insert into' in code_lower)
        indicators['has_update_statement'] = int('update' in code_lower and 'set' in code_lower)
        indicators['has_delete_statement'] = int('delete from' in code_lower)
        indicators['uses_statement_not_prepared'] = int('createstatement' in code_lower and 'preparedstatement' not in code_lower)
        indicators['has_sql_concat'] = int(bool(re.search(r'(select|insert|update|delete).*\+', code, re.IGNORECASE)))
        
        # Command Injection indicators
        indicators['uses_runtime_exec'] = int('runtime.getruntime().exec' in code_lower)
        indicators['uses_processbuilder'] = int('processbuilder' in code_lower)
        indicators['has_command_concat'] = int(bool(re.search(r'(exec|processbuilder).*\+', code, re.IGNORECASE)))
        
        # XSS indicators
        indicators['uses_innerhtml'] = int('innerhtml' in code_lower)
        indicators['uses_document_write'] = int('document.write' in code_lower)
        indicators['uses_eval'] = int('eval(' in code_lower)
        
        # Path Traversal indicators
        indicators['uses_file_operations'] = int(any(x in code_lower for x in ['file(', 'fileinputstream', 'fileoutputstream', 'path.get']))
        indicators['has_path_concat'] = int(bool(re.search(r'(file|path).*\+', code, re.IGNORECASE)))
        indicators['has_dotdot_pattern'] = int('..' in code)
        
        # Hard-coded credentials
        indicators['has_password_assignment'] = int(bool(re.search(r'password\s*=\s*["\'][^"\']{6,}["\']', code, re.IGNORECASE)))
        indicators['has_api_key'] = int(bool(re.search(r'(api[_-]?key|secret)\s*=\s*["\'][a-zA-Z0-9]{16,}["\']', code, re.IGNORECASE)))
        
        # Deserialization
        indicators['uses_readobject'] = int('readobject' in code_lower)
        indicators['uses_pickle'] = int('pickle.loads' in code_lower or 'unpickle' in code_lower)
        
        # Weak crypto
        indicators['uses_md5'] = int('md5' in code_lower)
        indicators['uses_sha1'] = int('sha1' in code_lower and 'sha256' not in code_lower)
        indicators['uses_des'] = int('des' in code_lower and 'aes' not in code_lower)
        
        return indicators
    
    @classmethod
    def extract_all_features(cls, code: str) -> np.ndarray:
        """Combina todas las features en un vector"""
        ast_features = cls.extract_java_ast_features(code)
        vuln_indicators = cls.extract_vulnerability_indicators(code)
        
        # Combinar en orden fijo
        feature_dict = {**ast_features, **vuln_indicators}
        feature_vector = np.array([feature_dict[k] for k in sorted(feature_dict.keys())])
        
        return feature_vector


class RealVulnerabilityDatasetGenerator:
    """
    Genera dataset de entrenamiento con código REAL vulnerable y seguro
    """
    
    def __init__(self):
        self.feature_extractor = AdvancedFeatureExtractor()
    
    def load_vulnerable_code_samples(self, repo_path: Path) -> List[Tuple[str, str]]:
        """
        Carga muestras de código REAL de repositorios vulnerables
        Retorna (code, cwe_label)
        """
        samples = []
        
        # Buscar archivos Java en el repositorio vulnerable
        java_files = list(repo_path.rglob('*.java'))
        
        logger.info(f"Found {len(java_files)} Java files in vulnerable repository")
        
        for java_file in java_files:
            try:
                code = java_file.read_text(encoding='utf-8', errors='ignore')
                
                # Analizar qué tipo de vulnerabilidad tiene basado en patrones REALES
                cwes = self.detect_cwe_from_real_code(code)
                
                if cwes:
                    # Dividir en chunks grandes
                    lines = code.split('\n')
                    for i in range(0, len(lines), 40):
                        chunk = '\n'.join(lines[i:i+60])
                        if len(chunk.strip()) > 50:
                            samples.append((chunk, cwes[0]))
                
            except Exception as e:
                continue
        
        logger.info(f"✅ Extracted {len(samples)} vulnerable code samples")
        return samples
    
    def detect_cwe_from_real_code(self, code: str) -> List[str]:
        """Detecta CWEs basado en análisis REAL del código"""
        cwes = []
        
        code_lower = code.lower()
        
        # SQL Injection
        if re.search(r'(select|insert|update|delete).*\+.*search', code, re.IGNORECASE):
            cwes.append('CWE-89')
        elif 'createstatement' in code_lower and 'executequery' in code_lower:
            cwes.append('CWE-89')
        
        # Command Injection
        if re.search(r'runtime\.getruntime\(\)\.exec.*\+', code, re.IGNORECASE):
            cwes.append('CWE-78')
        
        # Path Traversal
        if re.search(r'(file|path).*\+.*request', code, re.IGNORECASE):
            cwes.append('CWE-22')
        
        # XSS
        if 'innerhtml' in code_lower or ('eval(' in code_lower and 'request' in code_lower):
            cwes.append('CWE-79')
        
        # Hard-coded credentials
        if re.search(r'password\s*=\s*["\'][a-zA-Z0-9]{8,}["\']', code, re.IGNORECASE):
            cwes.append('CWE-798')
        
        # Deserialization
        if 'readobject' in code_lower or 'unserialize' in code_lower:
            cwes.append('CWE-502')
        
        return cwes
    
    def generate_safe_code_samples(self, repo_path: Path, count: int) -> List[Tuple[str, str]]:
        """
        Genera muestras de código SEGURO del mismo repositorio
        (código que NO tiene vulnerabilidades detectables)
        """
        samples = []
        
        java_files = list(repo_path.rglob('*.java'))
        
        for java_file in java_files:
            if len(samples) >= count:
                break
                
            try:
                code = java_file.read_text(encoding='utf-8', errors='ignore')
                
                # Solo incluir si NO tiene vulnerabilidades obvias
                if not self.detect_cwe_from_real_code(code):
                    lines = code.split('\n')
                    for i in range(0, len(lines), 40):
                        chunk = '\n'.join(lines[i:i+60])
                        if len(chunk.strip()) > 50 and len(samples) < count:
                            samples.append((chunk, 'SAFE'))
                
            except Exception as e:
                continue
        
        logger.info(f"✅ Generated {len(samples)} safe code samples")
        return samples
    
    def create_balanced_dataset(self) -> pd.DataFrame:
        """
        FASE 3 - MODIFY
        Crea dataset balanceado con código real vulnerable y seguro
        """
        logger.info("📊 Creating balanced dataset from REAL code...")
        
        # Cargar código del repositorio vulnerable
        vuln_repo = Path('/app/test_samples/javaspringvulny-main')
        
        # Extraer muestras vulnerables
        vulnerable_samples = self.load_vulnerable_code_samples(vuln_repo)
        
        # Extraer muestras seguras
        safe_samples = self.generate_safe_code_samples(vuln_repo, len(vulnerable_samples))
        
        # Combinar
        all_samples = vulnerable_samples + safe_samples
        
        logger.info(f"Total samples: {len(all_samples)}")
        logger.info(f"  Vulnerable: {len(vulnerable_samples)}")
        logger.info(f"  Safe: {len(safe_samples)}")
        
        # Extraer features
        logger.info("Extracting advanced features...")
        features_list = []
        labels = []
        
        for code, label in all_samples:
            features = self.feature_extractor.extract_all_features(code)
            features_list.append(features)
            labels.append(label)
        
        # Crear DataFrame
        X = np.array(features_list)
        y = np.array(labels)
        
        logger.info(f"✅ Dataset shape: {X.shape}")
        logger.info(f"✅ Label distribution: {Counter(y)}")
        
        return X, y


def main():
    logger.info("="*60)
    logger.info("SISTEMA DE MINERÍA DE DATOS PARA DETECCIÓN DE VULNERABILIDADES")
    logger.info("Metodología SEMMA")
    logger.info("="*60)
    
    # FASE 1 & 2: SAMPLE & EXPLORE
    miner = RealCodeMiner()
    cve_samples = miner.mine_from_local_cve_database()
    keywords = miner.extract_vulnerability_keywords(cve_samples)
    
    # FASE 3: MODIFY
    dataset_gen = RealVulnerabilityDatasetGenerator()
    X, y = dataset_gen.create_balanced_dataset()
    
    # Guardar dataset
    dataset_path = Path('/app/data/real_vulnerability_dataset.npz')
    np.savez(dataset_path, X=X, y=y)
    logger.info(f"✅ Dataset saved to {dataset_path}")
    
    logger.info("\n✅ Minería de datos completada!")
    logger.info("Siguiente paso: Entrenar modelos (run train_with_real_data.py)")


if __name__ == '__main__':
    main()
