#!/usr/bin/env python3
"""
Advanced Code Generator - Improved vulnerability pattern extraction
Processes ALL CVEs and generates 2000+ realistic training samples
"""

import json
import os
import random
from pathlib import Path
from collections import defaultdict

class AdvancedCodeGenerator:
    def __init__(self):
        self.data_dir = Path('/app/data')
        self.cve_dir = self.data_dir / 'cve_data' / '2025'
        
        # Enhanced CWE mapping with specific patterns
        self.cwe_patterns = {
            'CWE-89': {  # SQL Injection
                'keywords': ['sql injection', 'sql', 'query', 'select', 'insert', 'update', 'delete', 'drop', 'union'],
                'code_patterns': [
                    'query = "SELECT * FROM users WHERE id = \'" + user_id + "\'"',
                    'sql = "DELETE FROM items WHERE name = \'" + input + "\'"',
                    '"INSERT INTO logs VALUES (\'" + data + "\')"',
                    'db.execute("UPDATE users SET role=\'" + role + "\' WHERE id=" + id)',
                    'cursor.execute("SELECT * FROM {} WHERE name=\'{}\'".format(table, name))',
                ]
            },
            'CWE-78': {  # OS Command Injection
                'keywords': ['command injection', 'command execution', 'system', 'exec', 'shell', 'execute'],
                'code_patterns': [
                    'os.system("ping " + ip_address)',
                    'subprocess.call("curl " + url, shell=True)',
                    'Runtime.getRuntime().exec("ls " + directory)',
                    'exec("rm -rf " + path)',
                    '`cat #{filename}`',
                ]
            },
            'CWE-79': {  # Cross-Site Scripting (XSS)
                'keywords': ['xss', 'cross-site scripting', 'script injection', 'html injection'],
                'code_patterns': [
                    'res.send("<h1>Hello " + name + "</h1>")',
                    'document.innerHTML = userInput',
                    'echo "<div>" . $_GET["message"] . "</div>"',
                    'response.write("<p>" + request.getParameter("text") + "</p>")',
                    'return f"<html><body>{user_data}</body></html>"',
                ]
            },
            'CWE-22': {  # Path Traversal
                'keywords': ['path traversal', 'directory traversal', 'file inclusion', '../'],
                'code_patterns': [
                    'file = open("/uploads/" + filename)',
                    'File.read(user_path)',
                    'fs.readFile("./files/" + req.query.file)',
                    'include($_GET["page"] . ".php")',
                    'FileReader(basePath + userInput)',
                ]
            },
            'CWE-798': {  # Hard-coded Credentials
                'keywords': ['hardcoded', 'hard-coded', 'password', 'credential', 'secret', 'api key', 'token'],
                'code_patterns': [
                    'password = "Admin123"',
                    'API_KEY = "sk_live_abc123xyz789"',
                    'const SECRET = "supersecret123"',
                    'db_password = "P@ssw0rd"',
                    'private String apiToken = "ghp_abcdef123456";',
                ]
            },
            'CWE-327': {  # Weak Cryptography
                'keywords': ['md5', 'sha1', 'des', 'weak crypto', 'weak hash', 'insecure hash'],
                'code_patterns': [
                    'hashlib.md5(password.encode()).hexdigest()',
                    'MessageDigest.getInstance("MD5")',
                    'hash = Digest::MD5.hexdigest(data)',
                    'Cipher.getInstance("DES")',
                    'crypto.createHash("sha1")',
                ]
            },
            'CWE-502': {  # Insecure Deserialization
                'keywords': ['deserialization', 'unserialize', 'pickle', 'unmarshal'],
                'code_patterns': [
                    'pickle.loads(user_data)',
                    'unserialize($_COOKIE["user"])',
                    'YAML.load(request.body)',
                    'ObjectInputStream.readObject()',
                    'JSON.parse(untrusted_input)',
                ]
            },
            'CWE-352': {  # CSRF
                'keywords': ['csrf', 'cross-site request forgery', 'state changing operation'],
                'code_patterns': [
                    '@app.route("/delete", methods=["GET"])',
                    'if request.method == "POST": delete_user()',
                    'app.get("/transfer", (req, res) => { bank.transfer() })',
                ]
            },
            'CWE-611': {  # XXE
                'keywords': ['xxe', 'xml external entity', 'xml parsing'],
                'code_patterns': [
                    'doc = lxml.etree.parse(xml_data)',
                    'DocumentBuilder.parse(new InputSource(xml))',
                    'SimpleXMLElement($xmlString)',
                ]
            },
            'CWE-94': {  # Code Injection
                'keywords': ['code injection', 'eval', 'dynamic code'],
                'code_patterns': [
                    'eval(user_input)',
                    'Function(request.body)()',
                    'exec(compile(code, "<string>", "exec"))',
                ]
            }
        }
    
    def extract_advanced_patterns(self):
        """Extract patterns from ALL CVE files with better CWE mapping"""
        print(f"🔍 Scanning {self.cve_dir}...")
        
        cve_files = list(self.cve_dir.rglob('*.json'))
        print(f"📁 Found {len(cve_files)} CVE files")
        
        cwe_matches = defaultdict(list)
        
        # Process ALL CVEs (not just 1000)
        for idx, cve_file in enumerate(cve_files):
            if idx % 1000 == 0:
                print(f"   Processing CVE {idx}/{len(cve_files)}...")
            
            try:
                with open(cve_file) as f:
                    data = json.load(f)
                
                # Extract description
                desc = self._extract_description(data)
                if not desc:
                    continue
                
                # Match description against CWE patterns
                for cwe_id, info in self.cwe_patterns.items():
                    if any(keyword in desc for keyword in info['keywords']):
                        cwe_matches[cwe_id].append({
                            'file': str(cve_file),
                            'description': desc[:200]
                        })
            
            except Exception as e:
                continue
        
        print(f"\n📊 Pattern Extraction Results:")
        for cwe_id, matches in sorted(cwe_matches.items()):
            print(f"   {cwe_id}: {len(matches)} CVEs matched")
        
        return cwe_matches
    
    def _extract_description(self, data):
        """Extract English description from CVE JSON"""
        try:
            if 'containers' in data and 'cna' in data['containers']:
                descriptions = data['containers']['cna'].get('descriptions', [])
                for d in descriptions:
                    if d.get('lang') == 'en':
                        return d.get('value', '').lower()
        except:
            pass
        return ""
    
    def generate_advanced_training_data(self, cwe_matches):
        """Generate 2000+ realistic code samples with proper CWE labeling"""
        training_samples = []
        
        # Generate vulnerable code (50% of dataset)
        for cwe_id, patterns in self.cwe_patterns.items():
            cve_count = len(cwe_matches.get(cwe_id, []))
            
            # Generate proportional to CVE frequency
            sample_count = min(max(cve_count // 10, 50), 200)
            
            print(f"🔨 Generating {sample_count} samples for {cwe_id}...")
            
            for i in range(sample_count):
                # Pick random vulnerable pattern
                vuln_code = random.choice(patterns['code_patterns'])
                
                # Add context (function wrapper)
                contexts = [
                    self._wrap_python(vuln_code),
                    self._wrap_javascript(vuln_code),
                    self._wrap_java(vuln_code),
                    self._wrap_php(vuln_code)
                ]
                
                code = random.choice(contexts)
                
                training_samples.append({
                    'code': code,
                    'vulnerable': 1,
                    'cwe_id': cwe_id,
                    'vulnerability_type': self._get_vuln_name(cwe_id)
                })
        
        print(f"✅ Generated {len(training_samples)} vulnerable samples")
        
        # Generate safe code (50% of dataset)
        safe_count = len(training_samples)
        print(f"🔨 Generating {safe_count} safe code samples...")
        
        for i in range(safe_count):
            safe_code = self._generate_safe_code()
            training_samples.append({
                'code': safe_code,
                'vulnerable': 0,
                'cwe_id': 'SAFE',
                'vulnerability_type': 'Safe Code'
            })
        
        print(f"✅ Total training samples: {len(training_samples)}")
        
        # Shuffle
        random.shuffle(training_samples)
        
        return training_samples
    
    def _wrap_python(self, vuln_line):
        """Wrap vulnerable line in Python function"""
        templates = [
            f'''def process_user_input(user_data):
    """Process user input"""
    {vuln_line}
    return result''',
            
            f'''@app.route('/api/data')
def handle_request():
    user_input = request.args.get('input')
    {vuln_line}
    return response''',
            
            f'''class DataHandler:
    def process(self, data):
        {vuln_line}
        return output'''
        ]
        return random.choice(templates)
    
    def _wrap_javascript(self, vuln_line):
        """Wrap in JavaScript"""
        templates = [
            f'''function handleUserInput(data) {{
    {vuln_line};
    return result;
}}''',
            
            f'''app.post('/api/process', (req, res) => {{
    const input = req.body.data;
    {vuln_line};
    res.send(output);
}});''',
            
            f'''const processData = async (userInput) => {{
    {vuln_line};
    return data;
}};'''
        ]
        return random.choice(templates)
    
    def _wrap_java(self, vuln_line):
        """Wrap in Java"""
        templates = [
            f'''public class DataProcessor {{
    public String processInput(String userData) {{
        {vuln_line};
        return result;
    }}
}}''',
            
            f'''@PostMapping("/api/data")
public ResponseEntity<String> handleRequest(@RequestParam String input) {{
    {vuln_line};
    return ResponseEntity.ok(output);
}}'''
        ]
        return random.choice(templates)
    
    def _wrap_php(self, vuln_line):
        """Wrap in PHP"""
        templates = [
            f'''<?php
function processUserData($input) {{
    {vuln_line};
    return $result;
}}
?>''',
            
            f'''<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {{
    $user_input = $_POST['data'];
    {vuln_line};
    echo $output;
}}
?>'''
        ]
        return random.choice(templates)
    
    def _generate_safe_code(self):
        """Generate safe code examples"""
        safe_patterns = [
            # Parameterized queries
            '''def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()''',
            
            # Input validation
            '''function sanitizeInput(data) {
    return validator.escape(data.trim());
}''',
            
            # Proper authentication
            '''@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    return render_template('admin.html')''',
            
            # Secure hashing
            '''import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())''',
            
            # CSRF protection
            '''<form method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input type="text" name="data">
</form>''',
            
            # Environment variables for secrets
            '''const API_KEY = process.env.API_KEY;
if (!API_KEY) throw new Error('API_KEY not configured');''',
            
            # Output encoding
            '''from html import escape
safe_output = escape(user_input)''',
            
            # Prepared statements
            '''PreparedStatement pstmt = conn.prepareStatement(
    "SELECT * FROM users WHERE email = ?"
);
pstmt.setString(1, email);'''
        ]
        
        return random.choice(safe_patterns)
    
    def _get_vuln_name(self, cwe_id):
        """Map CWE to vulnerability name"""
        mapping = {
            'CWE-89': 'SQL Injection',
            'CWE-78': 'Command Injection',
            'CWE-79': 'Cross-Site Scripting (XSS)',
            'CWE-22': 'Path Traversal',
            'CWE-798': 'Hard-coded Credentials',
            'CWE-327': 'Weak Cryptography',
            'CWE-502': 'Insecure Deserialization',
            'CWE-352': 'CSRF',
            'CWE-611': 'XXE Injection',
            'CWE-94': 'Code Injection'
        }
        return mapping.get(cwe_id, 'Unknown Vulnerability')
    
    def save_training_data(self, samples):
        """Save to JSON"""
        output_file = self.data_dir / 'advanced_training_data.json'
        
        with open(output_file, 'w') as f:
            json.dump(samples, f, indent=2)
        
        print(f"\n💾 Training data saved: {output_file}")
        print(f"   Total samples: {len(samples)}")
        print(f"   Vulnerable: {sum(1 for s in samples if s['vulnerable'] == 1)}")
        print(f"   Safe: {sum(1 for s in samples if s['vulnerable'] == 0)}")
        
        # Print distribution by CWE
        print(f"\n📊 Distribution by CWE:")
        cwe_dist = defaultdict(int)
        for sample in samples:
            cwe_dist[sample['cwe_id']] += 1
        
        for cwe, count in sorted(cwe_dist.items()):
            vuln_name = self._get_vuln_name(cwe) if cwe != 'SAFE' else 'Safe Code'
            print(f"   {cwe} ({vuln_name}): {count}")
        
        return output_file

def main():
    print("🚀 Advanced Code Generator - Enhanced Training Data")
    print("=" * 60)
    
    generator = AdvancedCodeGenerator()
    
    # Step 1: Extract patterns from ALL CVEs
    print("\n📥 Step 1: Extracting patterns from CVE database...")
    cwe_matches = generator.extract_advanced_patterns()
    
    # Step 2: Generate training data
    print("\n🔨 Step 2: Generating advanced training data...")
    training_samples = generator.generate_advanced_training_data(cwe_matches)
    
    # Step 3: Save
    print("\n💾 Step 3: Saving training data...")
    output_file = generator.save_training_data(training_samples)
    
    print("\n✅ Advanced training data generation complete!")
    print(f"📁 Output: {output_file}")

if __name__ == '__main__':
    main()
