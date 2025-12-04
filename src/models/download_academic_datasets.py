#!/usr/bin/env python3
"""
Descarga y procesa datasets académicos PROFESIONALES
- BigVul: 188,636 functions (C/C++)
- CleanVul: 11,632 functions (Java, Python, C#, etc.)
- CVEFixes: Cross-language vulnerable/fixed pairs
- DiverseVul: Large-scale C/C++ dataset
"""

import requests
import zipfile
import tarfile
import json
import pandas as pd
from pathlib import Path
from loguru import logger
import subprocess
import time
from typing import List, Dict
import re

class AcademicDatasetDownloader:
    """
    Descarga datasets académicos de vulnerabilidades
    """
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Datasets disponibles
        self.datasets = {
            'bigvul': {
                'name': 'BigVul',
                'url': 'https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset',
                'description': '188,636 C/C++ functions from 348 projects',
                'files': ['MSR_data_cleaned.csv']
            },
            'cleanvul': {
                'name': 'CleanVul',
                'url': 'https://zenodo.org/record/8148830',
                'description': '11,632 functions (Java, Python, C#, etc.)',
                'note': 'Manual download required from Zenodo'
            },
            'cvefixes': {
                'name': 'CVEFixes',
                'url': 'https://github.com/secureIT-project/CVEfixes',
                'description': 'Cross-language CVE fixes (Java, Python, PHP, etc.)',
                'files': ['cve_fixes.csv']
            },
            'diversevul': {
                'name': 'DiverseVul',
                'url': 'https://github.com/wagner-group/diversevul',
                'description': 'Large-scale C/C++ vulnerable functions',
                'files': ['diversevul.csv']
            }
        }
    
    def download_bigvul(self) -> Path:
        """
        Descarga BigVul dataset (188K+ funciones)
        """
        logger.info("Downloading BigVul dataset...")
        
        bigvul_dir = self.output_dir / 'bigvul'
        bigvul_dir.mkdir(exist_ok=True)
        
        # Clonar repositorio
        repo_url = 'https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset.git'
        
        if not (bigvul_dir / '.git').exists():
            logger.info(f"Cloning {repo_url}")
            subprocess.run(
                ['git', 'clone', '--depth', '1', repo_url, str(bigvul_dir)],
                check=True,
                capture_output=True
            )
        else:
            logger.info("BigVul already cloned")
        
        # Buscar archivo CSV
        csv_file = bigvul_dir / 'MSR_data_cleaned.csv'
        if csv_file.exists():
            logger.info(f"✅ BigVul dataset: {csv_file}")
            return csv_file
        
        # Buscar en subdirectorios
        csv_files = list(bigvul_dir.rglob('*.csv'))
        if csv_files:
            logger.info(f"✅ Found CSV: {csv_files[0]}")
            return csv_files[0]
        
        logger.warning("BigVul CSV not found")
        return None
    
    def download_github_dataset(self, repo_url: str, dataset_name: str) -> Path:
        """
        Descarga dataset desde GitHub
        """
        logger.info(f"Downloading {dataset_name} from GitHub...")
        
        dataset_dir = self.output_dir / dataset_name.lower()
        dataset_dir.mkdir(exist_ok=True)
        
        if not (dataset_dir / '.git').exists():
            logger.info(f"Cloning {repo_url}")
            try:
                subprocess.run(
                    ['git', 'clone', '--depth', '1', repo_url, str(dataset_dir)],
                    check=True,
                    capture_output=True,
                    timeout=300
                )
                logger.info(f"✅ {dataset_name} cloned")
            except Exception as e:
                logger.error(f"Failed to clone {dataset_name}: {e}")
                return None
        else:
            logger.info(f"{dataset_name} already exists")
        
        return dataset_dir
    
    def process_bigvul(self, csv_path: Path) -> pd.DataFrame:
        """
        Procesa BigVul dataset
        """
        logger.info(f"Processing BigVul from {csv_path}")
        
        try:
            df = pd.read_csv(csv_path)
            logger.info(f"BigVul loaded: {len(df)} rows")
            logger.info(f"Columns: {df.columns.tolist()}")
            
            # Filtrar columnas relevantes
            if 'func_before' in df.columns and 'vul' in df.columns:
                # func_before = código vulnerable
                # vul = 0 (no vulnerable) o 1 (vulnerable)
                vulnerable = df[df['vul'] == 1]
                safe = df[df['vul'] == 0]
                
                logger.info(f"Vulnerable functions: {len(vulnerable)}")
                logger.info(f"Safe functions: {len(safe)}")
                
                return df
            
            return df
        
        except Exception as e:
            logger.error(f"Error processing BigVul: {e}")
            return None
    
    def extract_java_functions_from_bigvul(self, df: pd.DataFrame, limit: int = 5000) -> List[Dict]:
        """
        Extrae funciones Java/vulnerable de BigVul
        """
        samples = []
        
        # Filtrar solo funciones con código
        if 'func_before' not in df.columns or 'vul' not in df.columns:
            logger.warning("BigVul columns not found")
            return samples
        
        # Extraer vulnerables
        vulnerable = df[df['vul'] == 1].head(limit // 2)
        safe = df[df['vul'] == 0].head(limit // 2)
        
        logger.info(f"Extracting {len(vulnerable)} vulnerable + {len(safe)} safe")
        
        for idx, row in vulnerable.iterrows():
            code = str(row.get('func_before', ''))
            cwe_id = str(row.get('cwe_id', 'CWE-Unknown'))
            
            if len(code) > 50:
                samples.append({
                    'code': code,
                    'label': cwe_id if cwe_id.startswith('CWE-') else 'CWE-Unknown',
                    'language': 'c',
                    'source': 'BigVul',
                    'vulnerable': True
                })
        
        for idx, row in safe.iterrows():
            code = str(row.get('func_before', ''))
            
            if len(code) > 50:
                samples.append({
                    'code': code,
                    'label': 'SAFE',
                    'language': 'c',
                    'source': 'BigVul',
                    'vulnerable': False
                })
        
        logger.info(f"✅ Extracted {len(samples)} samples from BigVul")
        return samples
    
    def download_all_datasets(self) -> Dict[str, Path]:
        """
        Descarga todos los datasets disponibles
        """
        results = {}
        
        # BigVul
        bigvul_csv = self.download_bigvul()
        if bigvul_csv:
            results['bigvul'] = bigvul_csv
        
        # CVEFixes
        cvefixes_dir = self.download_github_dataset(
            'https://github.com/secureIT-project/CVEfixes.git',
            'CVEFixes'
        )
        if cvefixes_dir:
            results['cvefixes'] = cvefixes_dir
        
        # DiverseVul
        diversevul_dir = self.download_github_dataset(
            'https://github.com/wagner-group/diversevul.git',
            'DiverseVul'
        )
        if diversevul_dir:
            results['diversevul'] = diversevul_dir
        
        return results


def main():
    logger.info("="*60)
    logger.info("DOWNLOADING ACADEMIC VULNERABILITY DATASETS")
    logger.info("="*60)
    
    output_dir = Path('/app/data/academic_datasets')
    downloader = AcademicDatasetDownloader(output_dir)
    
    # Descargar datasets
    results = downloader.download_all_datasets()
    
    logger.info(f"\n{'='*60}")
    logger.info("DOWNLOADED DATASETS:")
    for name, path in results.items():
        logger.info(f"  {name}: {path}")
    logger.info(f"{'='*60}")
    
    # Procesar BigVul si existe
    if 'bigvul' in results:
        df = downloader.process_bigvul(results['bigvul'])
        
        if df is not None:
            # Extraer muestras
            samples = downloader.extract_java_functions_from_bigvul(df, limit=10000)
            
            # Guardar
            output_file = Path('/app/data/bigvul_samples.json')
            output_file.write_text(json.dumps({
                'total_samples': len(samples),
                'vulnerable': len([s for s in samples if s['vulnerable']]),
                'safe': len([s for s in samples if not s['vulnerable']]),
                'samples': samples
            }, indent=2))
            
            logger.info(f"\n✅ BigVul samples saved: {output_file}")
            logger.info(f"Total samples: {len(samples)}")


if __name__ == '__main__':
    main()
