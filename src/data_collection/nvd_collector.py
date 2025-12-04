"""
NVD Data Collector - SEMMA Phase: SAMPLE
Fetches vulnerability data from National Vulnerability Database API
"""

import requests
import time
from typing import List, Dict, Any, Optional
from loguru import logger
from datetime import datetime, timedelta
import pymongo
from ratelimit import limits, sleep_and_retry


class NVDCollector:
    """Collects vulnerability data from NVD API"""
    
    def __init__(self, mongo_uri: str, db_name: str, api_key: Optional[str] = None):
        """
        Initialize NVD Collector
        
        Args:
            mongo_uri: MongoDB connection string
            db_name: Database name
            api_key: NVD API key (optional, increases rate limits)
        """
        self.client = pymongo.MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.collection = self.db['nvd_vulnerabilities']
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Rate limits: 5 requests/30 seconds without key, 50/30 seconds with key
        self.rate_limit = 50 if api_key else 5
        self.rate_window = 30
        
        # Create indexes
        self.collection.create_index("cve_id", unique=True)
        self.collection.create_index("published_date")
        self.collection.create_index("last_modified_date")
        
        logger.info(f"NVD Collector initialized. Rate limit: {self.rate_limit}/{self.rate_window}s")
    
    @sleep_and_retry
    @limits(calls=5, period=30)
    def _make_api_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make rate-limited API request to NVD
        
        Args:
            params: Query parameters
            
        Returns:
            API response data
        """
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            raise
    
    def collect_recent_vulnerabilities(self, days: int = 30, results_per_page: int = 100) -> int:
        """
        Collect vulnerabilities published in the last N days
        
        Args:
            days: Number of days to look back
            results_per_page: Number of results per API call
            
        Returns:
            Number of vulnerabilities collected
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        logger.info(f"Collecting NVD data from {start_date.date()} to {end_date.date()}")
        
        return self.collect_by_date_range(
            start_date.isoformat(),
            end_date.isoformat(),
            results_per_page
        )
    
    def collect_by_date_range(
        self,
        pub_start_date: str,
        pub_end_date: str,
        results_per_page: int = 100
    ) -> int:
        """
        Collect vulnerabilities within a date range
        
        Args:
            pub_start_date: Start date (ISO format)
            pub_end_date: End date (ISO format)
            results_per_page: Results per page
            
        Returns:
            Number of vulnerabilities collected
        """
        start_index = 0
        total_collected = 0
        
        while True:
            params = {
                'pubStartDate': pub_start_date,
                'pubEndDate': pub_end_date,
                'resultsPerPage': results_per_page,
                'startIndex': start_index
            }
            
            try:
                logger.info(f"Fetching results starting at index {start_index}")
                response_data = self._make_api_request(params)
                
                vulnerabilities = response_data.get('vulnerabilities', [])
                total_results = response_data.get('totalResults', 0)
                
                if not vulnerabilities:
                    break
                
                # Process and save vulnerabilities
                for vuln_item in vulnerabilities:
                    cve_data = self._parse_nvd_item(vuln_item)
                    if cve_data:
                        self._save_to_db(cve_data)
                        total_collected += 1
                
                logger.info(f"Collected {total_collected}/{total_results} vulnerabilities")
                
                # Check if we've reached the end
                if start_index + results_per_page >= total_results:
                    break
                
                start_index += results_per_page
                time.sleep(6)  # Rate limiting safety margin
                
            except Exception as e:
                logger.error(f"Error collecting data at index {start_index}: {str(e)}")
                break
        
        logger.info(f"NVD collection complete. Total collected: {total_collected}")
        return total_collected
    
    def _parse_nvd_item(self, vuln_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse NVD API vulnerability item
        
        Args:
            vuln_item: Raw vulnerability data from API
            
        Returns:
            Parsed vulnerability data
        """
        try:
            cve = vuln_item.get('cve', {})
            
            cve_id = cve.get('id', '')
            
            # Get descriptions
            descriptions = cve.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS metrics
            metrics = cve.get('metrics', {})
            cvss_v31 = metrics.get('cvssMetricV31', [])
            cvss_v30 = metrics.get('cvssMetricV30', [])
            cvss_v2 = metrics.get('cvssMetricV2', [])
            
            cvss_score = 0.0
            severity = 'UNKNOWN'
            vector_string = ''
            
            if cvss_v31:
                cvss_data = cvss_v31[0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                vector_string = cvss_data.get('vectorString', '')
            elif cvss_v30:
                cvss_data = cvss_v30[0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                vector_string = cvss_data.get('vectorString', '')
            elif cvss_v2:
                cvss_data = cvss_v2[0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                # Map V2 score to severity
                if cvss_score >= 7.0:
                    severity = 'HIGH'
                elif cvss_score >= 4.0:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                vector_string = cvss_data.get('vectorString', '')
            
            # Get CWE information
            weaknesses = cve.get('weaknesses', [])
            cwes = []
            for weakness in weaknesses:
                descriptions = weakness.get('description', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        cwe_value = desc.get('value', '')
                        if cwe_value.startswith('CWE-'):
                            cwes.append(cwe_value)
            
            # Get CPE (affected configurations)
            configurations = cve.get('configurations', [])
            cpes = self._extract_cpes(configurations)
            
            # Get references
            references = cve.get('references', [])
            ref_urls = [ref.get('url', '') for ref in references]
            
            # Get dates
            published_date = cve.get('published', '')
            last_modified = cve.get('lastModified', '')
            
            # Get vulnerability status
            vuln_status = cve.get('vulnStatus', 'Unknown')
            
            parsed_data = {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'vector_string': vector_string,
                'cwes': cwes,
                'cpes': cpes,
                'references': ref_urls,
                'published_date': published_date,
                'last_modified_date': last_modified,
                'vulnerability_status': vuln_status,
                'source': 'NVD',
                'raw_data': vuln_item,
                'collected_at': datetime.utcnow().isoformat()
            }
            
            return parsed_data
            
        except Exception as e:
            logger.error(f"Error parsing NVD item: {str(e)}")
            return None
    
    def _extract_cpes(self, configurations: List[Dict]) -> List[str]:
        """Extract CPE strings from configurations"""
        cpes = []
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe_match in cpe_matches:
                    if cpe_match.get('vulnerable', False):
                        cpe_uri = cpe_match.get('criteria', '')
                        if cpe_uri:
                            cpes.append(cpe_uri)
        
        return cpes
    
    def _save_to_db(self, nvd_data: Dict[str, Any]) -> bool:
        """
        Save NVD data to MongoDB
        
        Args:
            nvd_data: Parsed NVD data
            
        Returns:
            True if saved successfully
        """
        try:
            self.collection.update_one(
                {'cve_id': nvd_data['cve_id']},
                {'$set': nvd_data},
                upsert=True
            )
            return True
        except Exception as e:
            logger.error(f"Error saving NVD data {nvd_data['cve_id']}: {str(e)}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get collection statistics"""
        total = self.collection.count_documents({})
        
        severity_counts = {}
        for severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN']:
            count = self.collection.count_documents({'severity': severity})
            severity_counts[severity] = count
        
        # Average CVSS score
        pipeline = [
            {'$group': {
                '_id': None,
                'avg_cvss': {'$avg': '$cvss_score'},
                'max_cvss': {'$max': '$cvss_score'},
                'min_cvss': {'$min': '$cvss_score'}
            }}
        ]
        cvss_stats = list(self.collection.aggregate(pipeline))
        
        return {
            'total_vulnerabilities': total,
            'severity_distribution': severity_counts,
            'cvss_statistics': cvss_stats[0] if cvss_stats else {}
        }
    
    def close(self):
        """Close database connection"""
        self.client.close()
        logger.info("NVD Collector connection closed")


def main():
    """Main execution function"""
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    
    mongo_uri = f"mongodb://{os.getenv('MONGO_ROOT_USER')}:{os.getenv('MONGO_ROOT_PASSWORD')}@{os.getenv('MONGO_HOST', 'localhost')}:{os.getenv('MONGO_PORT', 27017)}/"
    db_name = os.getenv('MONGO_DB', 'vulnerability_db')
    api_key = os.getenv('NVD_API_KEY')
    
    collector = NVDCollector(mongo_uri, db_name, api_key)
    
    try:
        # Collect recent vulnerabilities (last 30 days)
        collected = collector.collect_recent_vulnerabilities(days=30)
        
        # Display statistics
        stats = collector.get_statistics()
        logger.info(f"NVD Statistics: {stats}")
        
    finally:
        collector.close()


if __name__ == "__main__":
    main()
