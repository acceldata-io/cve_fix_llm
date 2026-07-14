#!/usr/bin/env python3
"""
Installation Verification Script
Tests all components of the Spark CVE Agent
"""

import sys
import os
from pathlib import Path

# Color codes for terminal
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BLUE = '\033[94m'

def print_success(msg):
    print(f"{GREEN}✅ {msg}{RESET}")

def print_error(msg):
    print(f"{RED}❌ {msg}{RESET}")

def print_warning(msg):
    print(f"{YELLOW}⚠️  {msg}{RESET}")

def print_info(msg):
    print(f"{BLUE}ℹ️  {msg}{RESET}")

def check_python_version():
    """Check Python version"""
    version = sys.version_info
    if version >= (3, 11):
        print_success(f"Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print_warning(f"Python {version.major}.{version.minor}.{version.micro} (3.11+ recommended)")
        return True

def check_imports():
    """Check required Python packages"""
    required = [
        'langchain',
        'openai',
        'chromadb',
        'lxml',
        'requests',
        'dotenv',
        'rich'
    ]
    
    all_ok = True
    for package in required:
        try:
            if package == 'dotenv':
                __import__('dotenv')
            else:
                __import__(package)
            print_success(f"Package: {package}")
        except ImportError:
            print_error(f"Package missing: {package}")
            all_ok = False
    
    return all_ok

def check_project_structure():
    """Check project directory structure"""
    required_dirs = [
        'src/agents',
        'src/storage',
        'src/tools',
        'data',
        'logs'
    ]
    
    all_ok = True
    for dir_path in required_dirs:
        if Path(dir_path).exists():
            print_success(f"Directory: {dir_path}")
        else:
            print_error(f"Directory missing: {dir_path}")
            all_ok = False
    
    return all_ok

def check_source_files():
    """Check source code files"""
    required_files = [
        'main.py',
        'src/agents/cve_agent.py',
        'src/storage/database.py',
        'src/storage/vector_store.py',
        'src/tools/spark_tools.py'
    ]
    
    all_ok = True
    for file_path in required_files:
        if Path(file_path).exists():
            print_success(f"File: {file_path}")
        else:
            print_error(f"File missing: {file_path}")
            all_ok = False
    
    return all_ok

def check_env_config():
    """Check .env configuration"""
    if not Path('.env').exists():
        print_error(".env file not found")
        print_info("Run: cp .env.template .env (if template exists)")
        return False
    
    print_success(".env file exists")
    
    # Check for required variables
    from dotenv import load_dotenv
    load_dotenv()
    
    required_vars = [
        'OPENAI_API_KEY',
        'SPARK_SOURCE_PATH',
        'JAVA_HOME'
    ]
    
    all_set = True
    for var in required_vars:
        value = os.getenv(var)
        if value and value != f'your_{var.lower()}_here':
            print_success(f"Config: {var} is set")
        else:
            print_warning(f"Config: {var} needs to be configured")
            all_set = False
    
    return all_set

def test_database():
    """Test database initialization"""
    try:
        # Add paths
        import sys
        from pathlib import Path
        current_dir = Path.cwd()
        sys.path.insert(0, str(current_dir))
        sys.path.insert(0, str(current_dir / 'src'))
        
        from src.storage.database import CVEDatabase
        
        test_db_path = './data/test_verification.db'
        db = CVEDatabase(test_db_path)
        
        # Test insert
        test_cve = {
            'cve_id': 'CVE-TEST-VERIFY',
            'severity': 'CRITICAL',
            'title': 'Verification Test',
            'description': 'Testing database',
            'affected_library': 'test:test',
            'current_version': '1.0.0',
            'fixed_version': '1.0.1',
            'cvss_score': 9.0
        }
        
        db.insert_cve(test_cve)
        pending = db.get_pending_cves(['CRITICAL'])
        
        db.close()
        
        # Cleanup
        if Path(test_db_path).exists():
            os.remove(test_db_path)
        
        if len(pending) > 0:
            print_success("SQLite database working")
            return True
        else:
            print_error("Database test failed")
            return False
            
    except Exception as e:
        print_error(f"Database test failed: {e}")
        return False

def test_vector_store():
    """Test ChromaDB"""
    try:
        # Add paths
        import sys
        from pathlib import Path
        current_dir = Path.cwd()
        sys.path.insert(0, str(current_dir))
        sys.path.insert(0, str(current_dir / 'src'))
        
        from src.storage.vector_store import CVEVectorStore
        
        test_path = './data/test_chroma_verify'
        vs = CVEVectorStore(test_path)
        
        test_cve = {
            'cve_id': 'CVE-TEST-VECTOR',
            'severity': 'HIGH',
            'title': 'Vector Test',
            'description': 'Testing vector store',
            'affected_library': 'test:vector',
            'current_version': '1.0.0',
            'cvss_score': 7.5
        }
        
        vs.add_cve('CVE-TEST-VECTOR', test_cve)
        stats = vs.get_collection_stats()
        
        # Cleanup
        import shutil
        if Path(test_path).exists():
            shutil.rmtree(test_path)
        
        if stats['cve_count'] > 0:
            print_success("ChromaDB vector store working")
            return True
        else:
            print_error("Vector store test failed")
            return False
            
    except Exception as e:
        print_error(f"Vector store test failed: {e}")
        return False

def check_external_tools():
    """Check external dependencies"""
    import subprocess
    
    tools = {
        'java': 'java -version',
        'mvn': 'mvn --version',
        'trivy': 'trivy --version'
    }
    
    all_ok = True
    for tool, cmd in tools.items():
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                print_success(f"Tool: {tool}")
            else:
                print_warning(f"Tool {tool} found but returned error")
        except FileNotFoundError:
            print_warning(f"Tool not found: {tool}")
            all_ok = False
        except Exception as e:
            print_warning(f"Tool {tool}: {e}")
    
    return all_ok

def main():
    """Run all verification checks"""
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║                                                            ║")
    print("║     Spark CVE Agent - Installation Verification           ║")
    print("║                                                            ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print()
    
    results = {}
    
    print("📋 Checking Python Version...")
    results['python'] = check_python_version()
    print()
    
    print("📦 Checking Python Packages...")
    results['packages'] = check_imports()
    print()
    
    print("📁 Checking Project Structure...")
    results['structure'] = check_project_structure()
    print()
    
    print("📄 Checking Source Files...")
    results['files'] = check_source_files()
    print()
    
    print("⚙️  Checking Configuration...")
    results['config'] = check_env_config()
    print()
    
    print("🗄️  Testing Database...")
    results['database'] = test_database()
    print()
    
    print("🔍 Testing Vector Store...")
    results['vector_store'] = test_vector_store()
    print()
    
    print("🔧 Checking External Tools...")
    results['tools'] = check_external_tools()
    print()
    
    # Summary
    print("═" * 60)
    print("VERIFICATION SUMMARY")
    print("═" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for check, result in results.items():
        status = f"{GREEN}PASS{RESET}" if result else f"{RED}FAIL{RESET}"
        print(f"{check.upper():20s} {status}")
    
    print("═" * 60)
    print(f"Results: {passed}/{total} checks passed")
    
    if passed == total:
        print()
        print(f"{GREEN}✅ All checks passed! System is ready to use.{RESET}")
        print()
        print("Next steps:")
        print("  1. Configure .env with your actual values")
        print("  2. Run: source venv/bin/activate")
        print("  3. Run: python main.py scan")
        return 0
    else:
        print()
        print(f"{YELLOW}⚠️  Some checks failed. Review errors above.{RESET}")
        print()
        print("Common fixes:")
        print("  - Missing packages: pip install -r requirements.txt")
        print("  - Missing .env: cp .env.template .env (then edit)")
        print("  - Missing tools: See README.md for installation")
        return 1

if __name__ == "__main__":
    sys.exit(main())