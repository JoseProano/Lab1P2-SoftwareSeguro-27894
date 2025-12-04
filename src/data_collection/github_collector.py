"""
GitHub Advisory Collector - SEMMA Phase: SAMPLE
Fetches security advisories from GitHub
"""

import requests
import time
from typing import List, Dict, Any, Optional
from loguru import logger
from datetime import datetime
import pymongo
from github import Github, GithubException


class GitHubAdvisoryCollector:
    """Collects security advisories from GitHub"""
    
    def __init__(self, mongo_uri: str, db_name: str, github_token: Optional[str] = None):
        """
        Initialize GitHub Advisory Collector
        
        Args:
            mongo_uri: MongoDB connection string
            db_name: Database name
            github_token: GitHub personal access token
        """
        self.client = pymongo.MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.collection = self.db['github_advisories']
        self.github_token = github_token
        
        if github_token:
            self.github = Github(github_token)
        else:
            self.github = Github()
            logger.warning("No GitHub token provided. Rate limits will be lower.")
        
        # Create indexes
        self.collection.create_index("ghsa_id", unique=True)
        self.collection.create_index("published_at")
        self.collection.create_index("severity")
        
        logger.info("GitHub Advisory Collector initialized")
    
    def collect_advisories(self, ecosystem: Optional[str] = None, max_advisories: int = 1000) -> int:
        """
        Collect security advisories from GitHub
        
        Args:
            ecosystem: Filter by ecosystem (e.g., 'npm', 'pip', 'maven')
            max_advisories: Maximum number of advisories to collect
            
        Returns:
            Number of advisories collected
        """
        collected = 0
        page = 1
        per_page = 100
        
        logger.info(f"Collecting GitHub advisories (ecosystem: {ecosystem or 'all'})")
        
        while collected < max_advisories:
            try:
                advisories = self._fetch_advisories_page(page, per_page, ecosystem)
                
                if not advisories:
                    logger.info("No more advisories to fetch")
                    break
                
                for advisory in advisories:
                    parsed_data = self._parse_advisory(advisory)
                    if parsed_data:
                        self._save_to_db(parsed_data)
                        collected += 1
                
                logger.info(f"Collected {collected} advisories so far...")
                
                if len(advisories) < per_page:
                    break
                
                page += 1
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Error collecting advisories at page {page}: {str(e)}")
                break
        
        logger.info(f"GitHub Advisory collection complete. Total: {collected}")
        return collected
    
    def _fetch_advisories_page(
        self,
        page: int,
        per_page: int,
        ecosystem: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch a page of advisories from GitHub API
        
        Args:
            page: Page number
            per_page: Results per page
            ecosystem: Ecosystem filter
            
        Returns:
            List of advisory data
        """
        url = "https://api.github.com/advisories"
        
        headers = {
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        
        if self.github_token:
            headers['Authorization'] = f'Bearer {self.github_token}'
        
        params = {
            'per_page': per_page,
            'page': page
        }
        
        if ecosystem:
            params['ecosystem'] = ecosystem
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            return []
    
    def collect_repository_advisories(self, repo_name: str) -> int:
        """
        Collect advisories for a specific repository
        
        Args:
            repo_name: Repository name (format: owner/repo)
            
        Returns:
            Number of advisories collected
        """
        collected = 0
        
        try:
            repo = self.github.get_repo(repo_name)
            
            # Note: This is a placeholder as PyGithub doesn't directly support
            # security advisories. We'd need to use the GraphQL API for this.
            logger.info(f"Checking repository: {repo_name}")
            
            # Collect from vulnerability alerts if available
            # This requires repo admin access
            try:
                alerts = repo.get_vulnerability_alert()
                logger.info(f"Repository has vulnerability alerts enabled: {alerts}")
            except GithubException:
                logger.info("No access to vulnerability alerts or not enabled")
            
        except Exception as e:
            logger.error(f"Error collecting repository advisories: {str(e)}")
        
        return collected
    
    def _parse_advisory(self, advisory: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse GitHub advisory data
        
        Args:
            advisory: Raw advisory data from API
            
        Returns:
            Parsed advisory data
        """
        try:
            ghsa_id = advisory.get('ghsa_id', '')
            cve_id = advisory.get('cve_id', '')
            
            summary = advisory.get('summary', '')
            description = advisory.get('description', '')
            
            severity = advisory.get('severity', 'UNKNOWN').upper()
            
            # Get CVSS score
            cvss = advisory.get('cvss', {})
            cvss_score = cvss.get('score', 0.0)
            cvss_vector = cvss.get('vector_string', '')
            
            # Get CWEs
            cwes = []
            cwe_list = advisory.get('cwes', [])
            for cwe in cwe_list:
                cwe_id = cwe.get('cwe_id', '')
                if cwe_id:
                    cwes.append(cwe_id)
            
            # Get vulnerabilities (affected packages)
            vulnerabilities = advisory.get('vulnerabilities', [])
            affected_packages = []
            
            for vuln in vulnerabilities:
                package = vuln.get('package', {})
                affected_packages.append({
                    'ecosystem': package.get('ecosystem', ''),
                    'name': package.get('name', ''),
                    'vulnerable_versions': vuln.get('vulnerable_version_range', ''),
                    'patched_versions': vuln.get('patched_versions', ''),
                    'first_patched': vuln.get('first_patched_version', '')
                })
            
            # Get references
            references = advisory.get('references', [])
            ref_urls = [ref.get('url', '') for ref in references if isinstance(ref, dict)]
            
            # Get dates
            published_at = advisory.get('published_at', '')
            updated_at = advisory.get('updated_at', '')
            withdrawn_at = advisory.get('withdrawn_at', '')
            
            parsed_data = {
                'ghsa_id': ghsa_id,
                'cve_id': cve_id,
                'summary': summary,
                'description': description,
                'severity': severity,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'cwes': cwes,
                'affected_packages': affected_packages,
                'references': ref_urls,
                'published_at': published_at,
                'updated_at': updated_at,
                'withdrawn_at': withdrawn_at,
                'source': 'GitHub',
                'raw_data': advisory,
                'collected_at': datetime.utcnow().isoformat()
            }
            
            return parsed_data
            
        except Exception as e:
            logger.error(f"Error parsing advisory: {str(e)}")
            return None
    
    def _save_to_db(self, advisory_data: Dict[str, Any]) -> bool:
        """
        Save advisory data to MongoDB
        
        Args:
            advisory_data: Parsed advisory data
            
        Returns:
            True if saved successfully
        """
        try:
            self.collection.update_one(
                {'ghsa_id': advisory_data['ghsa_id']},
                {'$set': advisory_data},
                upsert=True
            )
            return True
        except Exception as e:
            logger.error(f"Error saving advisory {advisory_data['ghsa_id']}: {str(e)}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get collection statistics"""
        total = self.collection.count_documents({})
        
        severity_counts = {}
        for severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN']:
            count = self.collection.count_documents({'severity': severity})
            severity_counts[severity] = count
        
        # Get ecosystem distribution
        pipeline = [
            {'$unwind': '$affected_packages'},
            {'$group': {
                '_id': '$affected_packages.ecosystem',
                'count': {'$sum': 1}
            }},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]
        ecosystems = list(self.collection.aggregate(pipeline))
        
        return {
            'total_advisories': total,
            'severity_distribution': severity_counts,
            'top_ecosystems': ecosystems
        }
    
    def close(self):
        """Close database connection"""
        self.client.close()
        logger.info("GitHub Advisory Collector connection closed")


def main():
    """Main execution function"""
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    
    mongo_uri = f"mongodb://{os.getenv('MONGO_ROOT_USER')}:{os.getenv('MONGO_ROOT_PASSWORD')}@{os.getenv('MONGO_HOST', 'localhost')}:{os.getenv('MONGO_PORT', 27017)}/"
    db_name = os.getenv('MONGO_DB', 'vulnerability_db')
    github_token = os.getenv('GITHUB_TOKEN')
    
    collector = GitHubAdvisoryCollector(mongo_uri, db_name, github_token)
    
    try:
        # Collect advisories for popular ecosystems
        ecosystems = ['npm', 'pip', 'maven', 'composer', 'nuget']
        
        for ecosystem in ecosystems:
            logger.info(f"Collecting advisories for {ecosystem}")
            collected = collector.collect_advisories(ecosystem=ecosystem, max_advisories=200)
            logger.info(f"Collected {collected} advisories for {ecosystem}")
        
        # Display statistics
        stats = collector.get_statistics()
        logger.info(f"GitHub Advisory Statistics: {stats}")
        
    finally:
        collector.close()


if __name__ == "__main__":
    main()
