"""
CVE Knowledge Base Extractor
Extracts actionable patterns from CVE database to improve code vulnerability detection
"""
import json
import re
from pathlib import Path
from collections import defaultdict, Counter
from loguru import logger
import os
import pymongo


class CVEKnowledgeExtractor:
    """Extract vulnerability patterns from CVE database for code analysis"""
    
    def __init__(self):
        # Connect to MongoDB
        mongo_uri = os.getenv('MONGO_URI', 'mongodb://mongodb:27017/')
        self.client = pymongo.MongoClient(mongo_uri)
        self.db = self.client['vulnerability_detection']
        
        self.cwe_patterns = defaultdict(list)
        self.keyword_patterns = defaultdict(set)
        self.severity_patterns = defaultdict(list)
        
        # Code-relevant CWEs we care about
        self.code_cwes = {
            'CWE-79': 'XSS',
            'CWE-89': 'SQL Injection',
            'CWE-78': 'Command Injection',
            'CWE-22': 'Path Traversal',
            'CWE-94': 'Code Injection',
            'CWE-95': 'Eval Injection',
            'CWE-434': 'File Upload',
            'CWE-502': 'Deserialization',
            'CWE-798': 'Hardcoded Credentials',
            'CWE-327': 'Weak Crypto',
            'CWE-326': 'Weak Encryption',
            'CWE-759': 'Password Hash',
            'CWE-319': 'Cleartext Transmission',
            'CWE-200': 'Information Exposure',
            'CWE-611': 'XXE',
            'CWE-918': 'SSRF',
            'CWE-601': 'Open Redirect',
            'CWE-77': 'Command Injection',
            'CWE-917': 'OGNL Injection',
            'CWE-915': 'Dynamic Code',
            'CWE-829': 'Untrusted Control',
            'CWE-470': 'Unsafe Reflection',
            'CWE-676': 'Dangerous Function',
        }
        
        # Keywords that indicate code vulnerability patterns
        self.code_keywords = [
            'eval', 'exec', 'system', 'shell', 'command', 'query', 'sql',
            'inject', 'deserialize', 'unserialize', 'pickle', 'yaml.load',
            'password', 'secret', 'api.key', 'token', 'credential',
            'md5', 'sha1', 'des', 'rc4', 'ecb',
            'file.read', 'file.write', 'path.join', 'open(',
            'request.', 'input', 'param', 'user.supplied',
            'concatenat', 'format.string', 'template',
            'reflection', 'dynamic.code', 'unsafe',
            'xxe', 'xml.parse', 'entity',
            'redirect', 'forward', 'sendredirect',
        ]
    
    def extract_cwe_patterns(self):
        """Extract code patterns associated with each CWE"""
        logger.info("🔍 Extracting CWE patterns from CVE database...")
        
        cve_collection = self.db['cve_data']
        
        for cwe_id, vuln_type in self.code_cwes.items():
            # Query CVEs with this CWE
            query = {'cwe_ids': {'$regex': cwe_id, '$options': 'i'}}
            cves = list(cve_collection.find(query).limit(100))
            
            if not cves:
                continue
            
            logger.info(f"  Found {len(cves)} CVEs for {cwe_id} ({vuln_type})")
            
            descriptions = []
            keywords = set()
            severities = []
            
            for cve in cves:
                desc = cve.get('description', '')
                descriptions.append(desc)
                
                # Extract keywords from description
                desc_lower = desc.lower()
                for keyword in self.code_keywords:
                    if keyword in desc_lower:
                        keywords.add(keyword)
                
                # Track severity patterns
                severity = cve.get('severity', cve.get('base_score', 0))
                severities.append(severity)
            
            self.cwe_patterns[cwe_id] = {
                'type': vuln_type,
                'sample_descriptions': descriptions[:10],
                'common_keywords': list(keywords),
                'avg_severity': sum(s for s in severities if isinstance(s, (int, float))) / max(len([s for s in severities if isinstance(s, (int, float))]), 1),
                'total_cves': len(cves)
            }
            
            self.keyword_patterns[vuln_type].update(keywords)
        
        logger.info(f"✅ Extracted patterns for {len(self.cwe_patterns)} CWEs")
        return self.cwe_patterns
    
    def generate_code_samples_from_cwe(self, cwe_id, vuln_type, count=10):
        """Generate synthetic code samples based on CVE descriptions for a CWE"""
        
        # Language-specific vulnerable patterns
        patterns = {
            'SQL Injection': [
                'query = "SELECT * FROM users WHERE id = \'" + user_id + "\'"',
                'cursor.execute("SELECT * FROM " + table_name)',
                'db.query(f"DELETE FROM {table} WHERE id={user_input}")',
                'sql = "INSERT INTO users VALUES (\'" + username + "\', \'" + password + "\')"',
                'SELECT * FROM products WHERE category = \'{}\'.format(category)',
            ],
            'Command Injection': [
                'os.system("ping " + host)',
                'exec("import " + module_name)',
                'subprocess.call("ls " + directory, shell=True)',
                'eval(user_input)',
                'Runtime.getRuntime().exec("cmd /c " + command)',
            ],
            'XSS': [
                'document.write(user_input)',
                'innerHTML = request.params.name',
                'echo "<div>" . $_GET["message"] . "</div>"',
                'res.send("<h1>" + user_comment + "</h1>")',
                'template.render(unsafe_html)',
            ],
            'Path Traversal': [
                'open("/var/www/" + filename)',
                'File(base_path + user_path)',
                'readFile(root + "/" + requested_file)',
                'with open(upload_dir + file_name) as f:',
                'fs.readFileSync(path.join(dir, user_input))',
            ],
            'Deserialization': [
                'pickle.loads(request.data)',
                'yaml.load(user_config)',
                'unserialize($_POST["data"])',
                'ObjectInputStream.readObject()',
                'JsonConvert.DeserializeObject(untrusted)',
            ],
            'Hardcoded Credentials': [
                'PASSWORD = "admin123"',
                'api_key = "sk-1234567890abcdef"',
                'DB_PASSWORD = "P@ssw0rd"',
                'private String secret = "hardcoded_secret";',
                'const TOKEN = "ghp_xxxxxxxxxxxx";',
            ],
            'Weak Crypto': [
                'hashlib.md5(password)',
                'Cipher.getInstance("DES/ECB/PKCS5Padding")',
                'crypto.createHash("sha1")',
                'MessageDigest.getInstance("MD5")',
                'hash = md5($password);',
            ],
        }
        
        samples = []
        if vuln_type in patterns:
            for pattern in patterns[vuln_type][:count]:
                samples.append(pattern)
        
        return samples
    
    def build_knowledge_base(self):
        """Build comprehensive knowledge base from CVE data"""
        logger.info("📚 Building CVE knowledge base...")
        
        knowledge = {
            'cwe_patterns': self.extract_cwe_patterns(),
            'keyword_to_vuln_type': {},
            'vuln_type_features': {},
        }
        
        # Map keywords to vulnerability types
        for vuln_type, keywords in self.keyword_patterns.items():
            for keyword in keywords:
                if keyword not in knowledge['keyword_to_vuln_type']:
                    knowledge['keyword_to_vuln_type'][keyword] = []
                knowledge['keyword_to_vuln_type'][keyword].append(vuln_type)
        
        # Generate feature templates for each vuln type
        for cwe_id, pattern_data in self.cwe_patterns.items():
            vuln_type = pattern_data['type']
            knowledge['vuln_type_features'][vuln_type] = {
                'cwe': cwe_id,
                'keywords': pattern_data['common_keywords'],
                'avg_severity': pattern_data['avg_severity'],
                'sample_count': pattern_data['total_cves'],
            }
        
        # Save knowledge base
        kb_path = Path('/app/models/cve_knowledge_base.json')
        with open(kb_path, 'w') as f:
            json.dump(knowledge, f, indent=2, default=str)
        
        logger.info(f"✅ Knowledge base saved: {kb_path}")
        logger.info(f"   CWE patterns: {len(knowledge['cwe_patterns'])}")
        logger.info(f"   Keyword mappings: {len(knowledge['keyword_to_vuln_type'])}")
        logger.info(f"   Vuln type features: {len(knowledge['vuln_type_features'])}")
        
        return knowledge
    
    def generate_enhanced_training_data(self):
        """Generate enhanced training dataset using CVE knowledge"""
        logger.info("🎯 Generating enhanced training dataset...")
        
        knowledge = self.build_knowledge_base()
        
        vulnerable_samples = []
        safe_samples = []
        
        # Generate vulnerable samples for each CWE pattern
        for cwe_id, pattern_data in knowledge['cwe_patterns'].items():
            vuln_type = pattern_data['type']
            code_samples = self.generate_code_samples_from_cwe(cwe_id, vuln_type, count=15)
            
            for code in code_samples:
                vulnerable_samples.append({
                    'code': code,
                    'vulnerable': 1,
                    'type': vuln_type,
                    'cwe': cwe_id,
                    'severity': pattern_data['avg_severity'],
                    'keywords': pattern_data['common_keywords']
                })
        
        # Generate safe code samples
        safe_patterns = [
            # Safe SQL
            'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            'query = db.query(User).filter(User.id == user_id)',
            'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")',
            
            # Safe command execution
            'subprocess.run(["ls", directory], capture_output=True)',
            'os.path.exists(safe_path)',
            
            # Safe file operations
            'with open(os.path.join(UPLOAD_DIR, secure_filename(filename))) as f:',
            'if os.path.abspath(path).startswith(BASE_DIR):',
            
            # Safe crypto
            'hashlib.sha256(password.encode())',
            'Cipher.getInstance("AES/GCM/NoPadding")',
            'bcrypt.hashpw(password, bcrypt.gensalt())',
            
            # Safe secrets
            'api_key = os.environ.get("API_KEY")',
            'password = config.get("database", "password")',
            'SECRET_KEY = os.getenv("SECRET_KEY")',
            
            # Safe deserialization
            'data = json.loads(request.body)',
            'yaml.safe_load(config_file)',
            
            # Safe XSS prevention
            'escape(user_input)',
            'sanitize_html(user_comment)',
            'textContent = user_data',
        ]
        
        for code in safe_patterns * 10:  # Repeat to balance dataset
            safe_samples.append({
                'code': code,
                'vulnerable': 0,
                'type': 'safe',
                'cwe': None,
                'severity': 0,
                'keywords': []
            })
        
        # Combine and save
        all_samples = vulnerable_samples + safe_samples
        
        dataset_path = Path('/app/data/enhanced_training_dataset.json')
        with open(dataset_path, 'w') as f:
            json.dump(all_samples, f, indent=2)
        
        logger.info(f"✅ Enhanced dataset saved: {dataset_path}")
        logger.info(f"   Vulnerable samples: {len(vulnerable_samples)}")
        logger.info(f"   Safe samples: {len(safe_samples)}")
        logger.info(f"   Total samples: {len(all_samples)}")
        
        return all_samples


if __name__ == "__main__":
    extractor = CVEKnowledgeExtractor()
    
    # Build knowledge base and generate training data
    knowledge = extractor.build_knowledge_base()
    dataset = extractor.generate_enhanced_training_data()
    
    logger.info("🎉 CVE knowledge extraction complete!")
