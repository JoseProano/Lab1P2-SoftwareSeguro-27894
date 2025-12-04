#!/usr/bin/env python3
"""
Procesa datasets académicos REALES para entrenamiento
- DiverseVul: 18,945 funciones C/C++
- BigVul: 188K+ funciones C/C++
- CVEFixes: Multi-lenguaje
Focus: C/C++ para máxima calidad
"""

import gdown
import json
import pandas as pd
from pathlib import Path
from loguru import logger
from typing import List, Dict
import re

class ProfessionalDatasetProcessor:
    """
    Procesa datasets académicos de alta calidad
    """
    
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    def download_diversevul(self) -> Path:
        """
        Descarga DiverseVul dataset desde Google Drive
        18,945 funciones C/C++
        """
        logger.info("Downloading DiverseVul dataset...")
        
        output_file = self.data_dir / 'diversevul_dataset.json'
        
        if output_file.exists():
            logger.info(f"DiverseVul already exists: {output_file}")
            return output_file
        
        # Google Drive file ID from URL
        file_id = '12IWKhmLhq7qn5B_iXgn5YerOQtkH-6RG'
        url = f'https://drive.google.com/uc?id={file_id}'
        
        try:
            logger.info("Downloading from Google Drive (this may take several minutes)...")
            gdown.download(url, str(output_file), quiet=False)
            logger.info(f"✅ Downloaded: {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Failed to download DiverseVul: {e}")
            return None
    
    def process_diversevul(self, json_path: Path, limit: int = 10000) -> List[Dict]:
        """
        Procesa DiverseVul JSON (formato JSONL - una línea por objeto)
        """
        logger.info(f"Processing DiverseVul from {json_path}")
        
        try:
            # JSONL format - one JSON object per line
            data = []
            with open(json_path, 'r') as f:
                for line in f:
                    if line.strip():
                        data.append(json.loads(line))
            
            logger.info(f"DiverseVul loaded: {len(data)} entries")
            
            samples = []
            vulnerable_count = 0
            safe_count = 0
            
            for entry in data[:limit]:
                func = entry.get('func', '')
                target = entry.get('target', 0)  # 0=safe, 1=vulnerable
                cwe_id = entry.get('cwe', '')
                project = entry.get('project', '')
                
                if len(func) < 50:
                    continue
                
                if target == 1:
                    # Vulnerable
                    label = f"CWE-{cwe_id}" if cwe_id else "CWE-Unknown"
                    samples.append({
                        'code': func,
                        'label': label,
                        'language': 'c',
                        'source': 'DiverseVul',
                        'project': project,
                        'vulnerable': True
                    })
                    vulnerable_count += 1
                else:
                    # Safe
                    samples.append({
                        'code': func,
                        'label': 'SAFE',
                        'language': 'c',
                        'source': 'DiverseVul',
                        'project': project,
                        'vulnerable': False
                    })
                    safe_count += 1
            
            logger.info(f"✅ Extracted {len(samples)} samples from DiverseVul")
            logger.info(f"  Vulnerable: {vulnerable_count}")
            logger.info(f"  Safe: {safe_count}")
            
            return samples
        
        except Exception as e:
            logger.error(f"Error processing DiverseVul: {e}")
            return []
    
    def process_bigvul_csv(self, csv_path: Path, limit: int = 5000) -> List[Dict]:
        """
        Procesa BigVul CSV
        """
        logger.info(f"Processing BigVul from {csv_path}")
        
        try:
            df = pd.read_csv(csv_path)
            logger.info(f"BigVul loaded: {len(df)} rows")
            logger.info(f"Columns: {list(df.columns)[:10]}")
            
            samples = []
            
            # BigVul tiene commit_id, files_changed, cwe_id
            for idx, row in df.head(limit).iterrows():
                cwe_id = str(row.get('cwe_id', ''))
                summary = str(row.get('summary', ''))
                
                # Extraer CWE limpio
                cwe_match = re.search(r'CWE-(\d+)', cwe_id)
                if cwe_match:
                    label = f"CWE-{cwe_match.group(1)}"
                else:
                    label = "CWE-Unknown"
                
                # Usar summary como "código" (es descripción pero tiene patrones)
                if len(summary) > 100:
                    samples.append({
                        'code': summary,
                        'label': label,
                        'language': 'c',
                        'source': 'BigVul',
                        'vulnerable': True
                    })
            
            logger.info(f"✅ Extracted {len(samples)} samples from BigVul")
            return samples
        
        except Exception as e:
            logger.error(f"Error processing BigVul: {e}")
            return []
    
    def create_balanced_dataset(self, all_samples: List[Dict]) -> List[Dict]:
        """
        Balancea dataset vulnerable/safe
        """
        vulnerable = [s for s in all_samples if s['vulnerable']]
        safe = [s for s in all_samples if not s['vulnerable']]
        
        logger.info(f"Before balancing: {len(vulnerable)} vulnerable, {len(safe)} safe")
        
        # Balance 50/50
        min_count = min(len(vulnerable), len(safe))
        
        balanced = vulnerable[:min_count] + safe[:min_count]
        
        logger.info(f"After balancing: {len(balanced)} total ({min_count} vulnerable, {min_count} safe)")
        
        return balanced
    
    def extract_cwe_distribution(self, samples: List[Dict]) -> Dict:
        """
        Analiza distribución de CWEs
        """
        cwe_counts = {}
        
        for sample in samples:
            label = sample.get('label', 'Unknown')
            cwe_counts[label] = cwe_counts.get(label, 0) + 1
        
        return dict(sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True))


def main():
    logger.info("="*60)
    logger.info("PROCESSING ACADEMIC DATASETS")
    logger.info("="*60)
    
    data_dir = Path('/app/data/academic_datasets')
    processor = ProfessionalDatasetProcessor(data_dir)
    
    all_samples = []
    
    # 1. Descargar y procesar DiverseVul
    logger.info("\n[1/2] DiverseVul Dataset")
    logger.info("-" * 60)
    
    diversevul_json = processor.download_diversevul()
    
    if diversevul_json and diversevul_json.exists():
        diversevul_samples = processor.process_diversevul(diversevul_json, limit=50000)
        all_samples.extend(diversevul_samples)
    
    # 2. Procesar BigVul CSV
    logger.info("\n[2/2] BigVul Dataset")
    logger.info("-" * 60)
    
    bigvul_csv = data_dir / 'bigvul' / 'all_c_cpp_release2.0.csv'
    if bigvul_csv.exists():
        bigvul_samples = processor.process_bigvul_csv(bigvul_csv, limit=5000)
        all_samples.extend(bigvul_samples)
    
    logger.info(f"\n{'='*60}")
    logger.info(f"TOTAL SAMPLES COLLECTED: {len(all_samples)}")
    logger.info(f"{'='*60}")
    
    # Balancear dataset
    balanced_samples = processor.create_balanced_dataset(all_samples)
    
    # Distribución CWE
    logger.info("\nCWE Distribution:")
    cwe_dist = processor.extract_cwe_distribution(balanced_samples)
    for cwe, count in list(cwe_dist.items())[:15]:
        logger.info(f"  {cwe}: {count}")
    
    # Guardar
    output_file = Path('/app/data/professional_vulnerability_dataset.json')
    output_data = {
        'total_samples': len(balanced_samples),
        'vulnerable': len([s for s in balanced_samples if s['vulnerable']]),
        'safe': len([s for s in balanced_samples if not s['vulnerable']]),
        'sources': ['DiverseVul', 'BigVul'],
        'language': 'C/C++',
        'cwe_distribution': cwe_dist,
        'samples': balanced_samples
    }
    
    output_file.write_text(json.dumps(output_data, indent=2))
    logger.info(f"\n✅ Professional dataset saved: {output_file}")
    logger.info(f"Total samples: {len(balanced_samples)}")
    logger.info(f"Vulnerable: {output_data['vulnerable']}")
    logger.info(f"Safe: {output_data['safe']}")


if __name__ == '__main__':
    main()
