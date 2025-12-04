"""
CVE Data Collector - SEMMA Phase: SAMPLE
Extracts vulnerability data from local CVE JSON files
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any
from loguru import logger
from tqdm import tqdm
import pymongo
from datetime import datetime


class CVECollector:
    """Collects and processes CVE data from local JSON files"""
    
    def __init__(self, mongo_uri: str, db_name: str, cve_data_path: str):
        """
        Initialize CVE Collector
        
        Args:
            mongo_uri: MongoDB connection string
            db_name: Database name
            cve_data_path: Path to CVE data directory
        """
        self.client = pymongo.MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.collection = self.db['cve_data']
        self.cve_data_path = Path(cve_data_path)
        
        # Create indexes for efficient queries
        self.collection.create_index("cve_id", unique=True)
        self.collection.create_index("published_date")
        self.collection.create_index("severity")
        
        logger.info(f"CVE Collector initialized. Database: {db_name}")
    
    def collect_from_directory(self, year: str = "2025") -> int:
        """
        Collect CVE data from directory structure
        
        Args:
            year: Year directory to scan
            
        Returns:
            Number of CVEs processed
        """
        year_path = self.cve_data_path / year
        
        if not year_path.exists():
            logger.error(f"Year directory not found: {year_path}")
            return 0
        
        cve_files = list(year_path.rglob("CVE-*.json"))
        logger.info(f"Found {len(cve_files)} CVE files in {year}")
        
        processed = 0
        skipped = 0
        errors = 0
        
        for cve_file in tqdm(cve_files, desc="Processing CVE files"):
            try:
                cve_data = self._parse_cve_file(cve_file)
                if cve_data:
                    self._save_to_db(cve_data)
                    processed += 1
                else:
                    skipped += 1
            except Exception as e:
                logger.error(f"Error processing {cve_file}: {str(e)}")
                errors += 1
        
        logger.info(f"CVE Collection complete. Processed: {processed}, Skipped: {skipped}, Errors: {errors}")
        return processed
    
    def _parse_cve_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Parse a single CVE JSON file
        
        Args:
            file_path: Path to CVE JSON file
            
        Returns:
            Parsed CVE data dictionary
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract relevant fields
            cve_id = data.get('cveMetadata', {}).get('cveId', file_path.stem)
            
            # Get description
            descriptions = data.get('containers', {}).get('cna', {}).get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            # Get severity/CVSS scores
            metrics = data.get('containers', {}).get('cna', {}).get('metrics', [])
            severity = self._extract_severity(metrics)
            cvss_score = self._extract_cvss_score(metrics)
            
            # Get affected products
            affected = data.get('containers', {}).get('cna', {}).get('affected', [])
            products = self._extract_products(affected)
            
            # Get references
            references = data.get('containers', {}).get('cna', {}).get('references', [])
            ref_urls = [ref.get('url', '') for ref in references]
            
            # Get dates
            published_date = data.get('cveMetadata', {}).get('datePublished', '')
            updated_date = data.get('cveMetadata', {}).get('dateUpdated', '')
            
            # Get problem types (CWE)
            problem_types = data.get('containers', {}).get('cna', {}).get('problemTypes', [])
            cwes = self._extract_cwes(problem_types)
            
            parsed_data = {
                'cve_id': cve_id,
                'description': description,
                'severity': severity,
                'cvss_score': cvss_score,
                'cwes': cwes,
                'affected_products': products,
                'references': ref_urls,
                'published_date': published_date,
                'updated_date': updated_date,
                'raw_data': data,
                'collected_at': datetime.utcnow().isoformat()
            }
            
            return parsed_data
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in {file_path}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing {file_path}: {str(e)}")
            return None
    
    def _extract_severity(self, metrics: List[Dict]) -> str:
        """Extract severity level from metrics"""
        if not metrics:
            return "UNKNOWN"
        
        for metric in metrics:
            if 'cvssV3_1' in metric:
                return metric['cvssV3_1'].get('baseSeverity', 'UNKNOWN')
            elif 'cvssV3_0' in metric:
                return metric['cvssV3_0'].get('baseSeverity', 'UNKNOWN')
            elif 'cvssV2_0' in metric:
                score = metric['cvssV2_0'].get('baseScore', 0)
                if score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
        
        return "UNKNOWN"
    
    def _extract_cvss_score(self, metrics: List[Dict]) -> float:
        """Extract CVSS base score from metrics"""
        if not metrics:
            return 0.0
        
        for metric in metrics:
            if 'cvssV3_1' in metric:
                return float(metric['cvssV3_1'].get('baseScore', 0.0))
            elif 'cvssV3_0' in metric:
                return float(metric['cvssV3_0'].get('baseScore', 0.0))
            elif 'cvssV2_0' in metric:
                return float(metric['cvssV2_0'].get('baseScore', 0.0))
        
        return 0.0
    
    def _extract_products(self, affected: List[Dict]) -> List[Dict[str, str]]:
        """Extract affected products information"""
        products = []
        
        for item in affected:
            vendor = item.get('vendor', 'Unknown')
            product = item.get('product', 'Unknown')
            versions = item.get('versions', [])
            
            version_list = []
            for ver in versions:
                version_list.append(ver.get('version', 'Unknown'))
            
            products.append({
                'vendor': vendor,
                'product': product,
                'versions': version_list
            })
        
        return products
    
    def _extract_cwes(self, problem_types: List[Dict]) -> List[str]:
        """Extract CWE identifiers from problem types"""
        cwes = []
        
        for problem_type in problem_types:
            descriptions = problem_type.get('descriptions', [])
            for desc in descriptions:
                cwe_id = desc.get('cweId', '')
                if cwe_id:
                    cwes.append(cwe_id)
        
        return cwes
    
    def _save_to_db(self, cve_data: Dict[str, Any]) -> bool:
        """
        Save CVE data to MongoDB
        
        Args:
            cve_data: Parsed CVE data
            
        Returns:
            True if saved successfully
        """
        try:
            self.collection.update_one(
                {'cve_id': cve_data['cve_id']},
                {'$set': cve_data},
                upsert=True
            )
            return True
        except Exception as e:
            logger.error(f"Error saving CVE {cve_data['cve_id']}: {str(e)}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get collection statistics"""
        total = self.collection.count_documents({})
        
        severity_counts = {}
        for severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN']:
            count = self.collection.count_documents({'severity': severity})
            severity_counts[severity] = count
        
        # Get CWE distribution
        pipeline = [
            {'$unwind': '$cwes'},
            {'$group': {'_id': '$cwes', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]
        top_cwes = list(self.collection.aggregate(pipeline))
        
        return {
            'total_cves': total,
            'severity_distribution': severity_counts,
            'top_cwes': top_cwes
        }
    
    def close(self):
        """Close database connection"""
        self.client.close()
        logger.info("CVE Collector connection closed")


def main():
    """Main execution function"""
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    
    mongo_uri = f"mongodb://{os.getenv('MONGO_ROOT_USER')}:{os.getenv('MONGO_ROOT_PASSWORD')}@{os.getenv('MONGO_HOST', 'localhost')}:{os.getenv('MONGO_PORT', 27017)}/"
    db_name = os.getenv('MONGO_DB', 'vulnerability_db')
    cve_data_path = "/app/cve_data"
    
    collector = CVECollector(mongo_uri, db_name, cve_data_path)
    
    try:
        # Collect CVE data from 2025 directory
        processed = collector.collect_from_directory("2025")
        
        # Display statistics
        stats = collector.get_statistics()
        logger.info(f"Collection Statistics: {json.dumps(stats, indent=2)}")
        
    finally:
        collector.close()


if __name__ == "__main__":
    main()
