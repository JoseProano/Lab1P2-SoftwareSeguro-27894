"""
Exploratory Data Analysis (EDA) - SEMMA Phase: EXPLORE
Analyzes and visualizes vulnerability data
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, Any, List
from loguru import logger
import pymongo
from pathlib import Path
import json
from datetime import datetime


class VulnerabilityEDA:
    """Performs exploratory data analysis on vulnerability data"""
    
    def __init__(self, mongo_uri: str, db_name: str, output_dir: str = "./reports"):
        """
        Initialize EDA module
        
        Args:
            mongo_uri: MongoDB connection string
            db_name: Database name
            output_dir: Directory for saving visualizations
        """
        self.client = pymongo.MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set visualization style
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (12, 6)
        
        logger.info(f"EDA module initialized. Output: {output_dir}")
    
    def load_data(self) -> pd.DataFrame:
        """
        Load and combine data from all collections
        
        Returns:
            Combined DataFrame
        """
        logger.info("Loading data from MongoDB...")
        
        # Load CVE data
        cve_data = list(self.db.cve_data.find())
        df_cve = pd.DataFrame(cve_data)
        if not df_cve.empty:
            df_cve['source'] = 'CVE'
        
        # Load NVD data
        nvd_data = list(self.db.nvd_vulnerabilities.find())
        df_nvd = pd.DataFrame(nvd_data)
        if not df_nvd.empty:
            df_nvd['source'] = 'NVD'
        
        # Load GitHub advisories
        github_data = list(self.db.github_advisories.find())
        df_github = pd.DataFrame(github_data)
        if not df_github.empty:
            df_github['source'] = 'GitHub'
        
        # Combine dataframes
        dfs = [df for df in [df_cve, df_nvd, df_github] if not df.empty]
        
        if not dfs:
            logger.error("No data found in any collection")
            return pd.DataFrame()
        
        # Standardize columns for merging
        df_combined = self._standardize_dataframes(dfs)
        
        logger.info(f"Loaded {len(df_combined)} total vulnerabilities")
        return df_combined
    
    def _standardize_dataframes(self, dfs: List[pd.DataFrame]) -> pd.DataFrame:
        """Standardize and combine dataframes from different sources"""
        standardized = []
        
        for df in dfs:
            if df.empty:
                continue
            
            # Common columns to extract
            std_df = pd.DataFrame()
            
            # Handle different ID columns
            if 'cve_id' in df.columns:
                std_df['id'] = df['cve_id']
            elif 'ghsa_id' in df.columns:
                std_df['id'] = df['ghsa_id']
            
            # Description
            if 'description' in df.columns:
                std_df['description'] = df['description']
            elif 'summary' in df.columns:
                std_df['description'] = df['summary']
            
            # CVSS Score
            if 'cvss_score' in df.columns:
                std_df['cvss_score'] = pd.to_numeric(df['cvss_score'], errors='coerce')
            
            # Severity
            if 'severity' in df.columns:
                std_df['severity'] = df['severity'].str.upper()
            
            # CWEs
            if 'cwes' in df.columns:
                std_df['cwes'] = df['cwes']
            
            # Dates
            if 'published_date' in df.columns:
                std_df['published_date'] = pd.to_datetime(df['published_date'], errors='coerce')
            elif 'published_at' in df.columns:
                std_df['published_date'] = pd.to_datetime(df['published_at'], errors='coerce')
            
            # Source
            if 'source' in df.columns:
                std_df['source'] = df['source']
            
            standardized.append(std_df)
        
        return pd.concat(standardized, ignore_index=True)
    
    def generate_summary_statistics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Generate summary statistics
        
        Args:
            df: DataFrame with vulnerability data
            
        Returns:
            Dictionary with statistics
        """
        logger.info("Generating summary statistics...")
        
        stats = {
            'total_vulnerabilities': len(df),
            'unique_ids': df['id'].nunique() if 'id' in df.columns else 0,
            'sources': df['source'].value_counts().to_dict() if 'source' in df.columns else {},
        }
        
        # Date range statistics
        if 'published_date' in df.columns:
            date_col = pd.to_datetime(df['published_date'], errors='coerce')
            date_col = date_col.dropna()
            if not date_col.empty:
                stats['date_range'] = {
                    'earliest': date_col.min().isoformat(),
                    'latest': date_col.max().isoformat()
                }
            else:
                stats['date_range'] = {'earliest': None, 'latest': None}
        else:
            stats['date_range'] = {'earliest': None, 'latest': None}
        
        # CVSS statistics
        if 'cvss_score' in df.columns:
            cvss_data = df['cvss_score'].dropna()
            if not cvss_data.empty:
                stats['cvss'] = {
                    'mean': float(cvss_data.mean()),
                    'median': float(cvss_data.median()),
                    'std': float(cvss_data.std()),
                    'min': float(cvss_data.min()),
                    'max': float(cvss_data.max())
                }
        
        # Severity distribution
        if 'severity' in df.columns:
            stats['severity_distribution'] = df['severity'].value_counts().to_dict()
        
        # CWE statistics
        if 'cwes' in df.columns:
            all_cwes = []
            for cwes in df['cwes'].dropna():
                if isinstance(cwes, list):
                    all_cwes.extend(cwes)
            
            if all_cwes:
                cwe_counts = pd.Series(all_cwes).value_counts().head(10)
                stats['top_cwes'] = cwe_counts.to_dict()
        
        # Save statistics to file
        stats_file = self.output_dir / 'summary_statistics.json'
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2, default=str)
        
        logger.info(f"Summary statistics saved to {stats_file}")
        return stats
    
    def plot_severity_distribution(self, df: pd.DataFrame):
        """Plot severity distribution"""
        if 'severity' not in df.columns:
            logger.warning("No severity column found")
            return
        
        logger.info("Plotting severity distribution...")
        
        severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN']
        severity_counts = df['severity'].value_counts()
        
        # Filter to only include severities that exist in the data
        severity_order = [s for s in severity_order if s in severity_counts.index]
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Bar plot
        severity_counts.reindex(severity_order).plot(kind='bar', ax=ax1, color=['green', 'yellow', 'orange', 'red', 'gray'][:len(severity_order)])
        ax1.set_title('Vulnerability Severity Distribution', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Severity Level')
        ax1.set_ylabel('Count')
        ax1.tick_params(axis='x', rotation=45)
        
        # Pie chart
        severity_counts.reindex(severity_order).plot(
            kind='pie',
            ax=ax2,
            autopct='%1.1f%%',
            colors=['green', 'yellow', 'orange', 'red', 'gray'][:len(severity_order)]
        )
        ax2.set_title('Severity Percentage', fontsize=14, fontweight='bold')
        ax2.set_ylabel('')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'severity_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info("Severity distribution plot saved")
    
    def plot_cvss_distribution(self, df: pd.DataFrame):
        """Plot CVSS score distribution"""
        if 'cvss_score' not in df.columns:
            logger.warning("No CVSS score column found")
            return
        
        logger.info("Plotting CVSS distribution...")
        
        cvss_data = df['cvss_score'].dropna()
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # Histogram
        axes[0, 0].hist(cvss_data, bins=30, edgecolor='black', alpha=0.7)
        axes[0, 0].set_title('CVSS Score Distribution', fontsize=12, fontweight='bold')
        axes[0, 0].set_xlabel('CVSS Score')
        axes[0, 0].set_ylabel('Frequency')
        axes[0, 0].axvline(cvss_data.mean(), color='red', linestyle='--', label=f'Mean: {cvss_data.mean():.2f}')
        axes[0, 0].legend()
        
        # Box plot
        axes[0, 1].boxplot(cvss_data)
        axes[0, 1].set_title('CVSS Score Box Plot', fontsize=12, fontweight='bold')
        axes[0, 1].set_ylabel('CVSS Score')
        
        # KDE plot
        cvss_data.plot(kind='kde', ax=axes[1, 0])
        axes[1, 0].set_title('CVSS Score Density', fontsize=12, fontweight='bold')
        axes[1, 0].set_xlabel('CVSS Score')
        axes[1, 0].set_ylabel('Density')
        
        # CVSS ranges
        cvss_ranges = pd.cut(cvss_data, bins=[0, 3.9, 6.9, 8.9, 10], labels=['Low', 'Medium', 'High', 'Critical'])
        range_counts = cvss_ranges.value_counts().sort_index()
        range_counts.plot(kind='bar', ax=axes[1, 1], color=['green', 'yellow', 'orange', 'red'])
        axes[1, 1].set_title('CVSS Score Ranges', fontsize=12, fontweight='bold')
        axes[1, 1].set_xlabel('CVSS Range')
        axes[1, 1].set_ylabel('Count')
        axes[1, 1].tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'cvss_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info("CVSS distribution plot saved")
    
    def plot_temporal_trends(self, df: pd.DataFrame):
        """Plot temporal trends of vulnerabilities"""
        if 'published_date' not in df.columns:
            logger.warning("No published date column found")
            return
        
        logger.info("Plotting temporal trends...")
        
        df_temporal = df.dropna(subset=['published_date']).copy()
        # Convert to datetime if not already
        df_temporal['published_date'] = pd.to_datetime(df_temporal['published_date'], errors='coerce')
        df_temporal = df_temporal.dropna(subset=['published_date'])
        
        if len(df_temporal) == 0:
            logger.warning("No valid dates found for temporal analysis")
            return
            
        df_temporal['year_month'] = df_temporal['published_date'].dt.to_period('M')
        
        monthly_counts = df_temporal.groupby('year_month').size()
        
        fig, ax = plt.subplots(figsize=(15, 6))
        monthly_counts.plot(kind='line', ax=ax, marker='o')
        ax.set_title('Vulnerability Trends Over Time', fontsize=14, fontweight='bold')
        ax.set_xlabel('Date')
        ax.set_ylabel('Number of Vulnerabilities')
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'temporal_trends.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info("Temporal trends plot saved")
    
    def plot_cwe_distribution(self, df: pd.DataFrame, top_n: int = 15):
        """Plot CWE distribution"""
        if 'cwes' not in df.columns:
            logger.warning("No CWE column found")
            return
        
        logger.info("Plotting CWE distribution...")
        
        all_cwes = []
        for cwes in df['cwes'].dropna():
            if isinstance(cwes, list):
                all_cwes.extend(cwes)
        
        if not all_cwes:
            logger.warning("No CWE data found")
            return
        
        cwe_counts = pd.Series(all_cwes).value_counts().head(top_n)
        
        fig, ax = plt.subplots(figsize=(12, 8))
        cwe_counts.plot(kind='barh', ax=ax)
        ax.set_title(f'Top {top_n} CWE Categories', fontsize=14, fontweight='bold')
        ax.set_xlabel('Count')
        ax.set_ylabel('CWE')
        ax.invert_yaxis()
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'cwe_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info("CWE distribution plot saved")
    
    def plot_correlation_heatmap(self, df: pd.DataFrame):
        """Plot correlation heatmap for numerical features"""
        logger.info("Plotting correlation heatmap...")
        
        # Select numerical columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        if len(numeric_cols) < 2:
            logger.warning("Not enough numerical columns for correlation analysis")
            return
        
        correlation_matrix = df[numeric_cols].corr()
        
        fig, ax = plt.subplots(figsize=(10, 8))
        sns.heatmap(correlation_matrix, annot=True, fmt='.2f', cmap='coolwarm', center=0, ax=ax)
        ax.set_title('Feature Correlation Heatmap', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'correlation_heatmap.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info("Correlation heatmap saved")
    
    def generate_report(self, df: pd.DataFrame) -> str:
        """
        Generate comprehensive EDA report
        
        Args:
            df: DataFrame with vulnerability data
            
        Returns:
            Path to generated report
        """
        logger.info("Generating comprehensive EDA report...")
        
        # Generate all visualizations
        self.plot_severity_distribution(df)
        self.plot_cvss_distribution(df)
        self.plot_temporal_trends(df)
        self.plot_cwe_distribution(df)
        self.plot_correlation_heatmap(df)
        
        # Generate summary statistics
        stats = self.generate_summary_statistics(df)
        
        # Create HTML report
        report_html = self._create_html_report(stats)
        report_path = self.output_dir / 'eda_report.html'
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        logger.info(f"EDA report generated: {report_path}")
        return str(report_path)
    
    def _create_html_report(self, stats: Dict[str, Any]) -> str:
        """Create HTML report with statistics and visualizations"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Data EDA Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
                h2 {{ color: #34495e; margin-top: 30px; }}
                .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
                .stat-card {{ background: #ecf0f1; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db; }}
                .stat-value {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
                .stat-label {{ color: #7f8c8d; font-size: 14px; }}
                .visualization {{ margin: 30px 0; text-align: center; }}
                .visualization img {{ max-width: 100%; border: 1px solid #ddd; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #3498db; color: white; }}
                tr:hover {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 Vulnerability Data Analysis Report</h1>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>📊 Summary Statistics</h2>
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-value">{stats.get('total_vulnerabilities', 0):,}</div>
                        <div class="stat-label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{stats.get('unique_ids', 0):,}</div>
                        <div class="stat-label">Unique Identifiers</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{stats.get('cvss', {}).get('mean', 0):.2f}</div>
                        <div class="stat-label">Average CVSS Score</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{len(stats.get('sources', {}))}</div>
                        <div class="stat-label">Data Sources</div>
                    </div>
                </div>
                
                <h2>📈 Visualizations</h2>
                
                <div class="visualization">
                    <h3>Severity Distribution</h3>
                    <img src="severity_distribution.png" alt="Severity Distribution">
                </div>
                
                <div class="visualization">
                    <h3>CVSS Score Analysis</h3>
                    <img src="cvss_distribution.png" alt="CVSS Distribution">
                </div>
                
                <div class="visualization">
                    <h3>Temporal Trends</h3>
                    <img src="temporal_trends.png" alt="Temporal Trends">
                </div>
                
                <div class="visualization">
                    <h3>Top CWE Categories</h3>
                    <img src="cwe_distribution.png" alt="CWE Distribution">
                </div>
                
                <h2>🔝 Top CWEs</h2>
                <table>
                    <tr>
                        <th>CWE</th>
                        <th>Count</th>
                    </tr>
        """
        
        for cwe, count in list(stats.get('top_cwes', {}).items())[:10]:
            html += f"<tr><td>{cwe}</td><td>{count}</td></tr>"
        
        html += """
                </table>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def close(self):
        """Close database connection"""
        self.client.close()
        logger.info("EDA connection closed")


def main():
    """Main execution function"""
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    
    mongo_uri = f"mongodb://{os.getenv('MONGO_ROOT_USER')}:{os.getenv('MONGO_ROOT_PASSWORD')}@{os.getenv('MONGO_HOST', 'localhost')}:{os.getenv('MONGO_PORT', 27017)}/"
    db_name = os.getenv('MONGO_DB', 'vulnerability_db')
    
    eda = VulnerabilityEDA(mongo_uri, db_name)
    
    try:
        # Load data
        df = eda.load_data()
        
        if df.empty:
            logger.error("No data to analyze")
            return
        
        # Generate report
        report_path = eda.generate_report(df)
        logger.info(f"EDA complete. Report: {report_path}")
        
    finally:
        eda.close()


if __name__ == "__main__":
    main()
