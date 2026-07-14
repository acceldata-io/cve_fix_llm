# Example Usage & Testing Guide

This guide walks through using the Spark CVE Remediation Agent step by step.

## Prerequisites Check

Before starting, ensure you have:

```bash
# Check all prerequisites
python --version    # Should be 3.11+
java -version       # Should be Java 11
mvn --version       # Should be 3.6+
trivy --version     # Should be installed
```

## Phase 1: Initial Setup (First Time Only)

### 1.1 Run Setup Script

```bash
cd ~/spark-cve-agent
chmod +x setup.sh
./setup.sh
```

### 1.2 Configure Environment

Edit `.env` file:

```bash
nano .env
```

Set these values:

```bash
# Get OpenAI API key from: https://platform.openai.com/api-keys
OPENAI_API_KEY=sk-proj-xxxxx

# Your Spark source path
SPARK_SOURCE_PATH=/Users/senthilkumar/Documents/Senthilkumar/AccelData/gitups/Spark_Adoc/spark355/spark3

# Your Java home (run: /usr/libexec/java_home to find it)
JAVA_HOME=/Library/Java/JavaVirtualMachines/corretto-11.0.23/Contents/Home
```

### 1.3 Activate Environment

```bash
source venv/bin/activate
```

You should see `(venv)` in your prompt.

## Phase 2: Exploration & Analysis

### 2.1 Run Initial Scan

```bash
# Basic scan for CRITICAL and HIGH vulnerabilities
python main.py scan
```

**Expected Output:**
```
🔍 Running Trivy Vulnerability Scan

Scanning... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

     Vulnerability Scan Results      
┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ CRITICAL │ 5     │
│ HIGH     │ 15    │
│ MEDIUM   │ 25    │
└──────────┴───────┘

✅ Total CVEs found: 45
Scan results saved to: ./data/scans/trivy_scan_20241204_143022.json
```

### 2.2 Analyze Dependencies

```bash
# Extract and analyze all dependencies
python main.py analyze --output dependencies.json
```

**Expected Output:**
```
📦 Analyzing Dependencies

     Dependencies (234 total)      
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Group ID          ┃ Artifact ID     ┃ Version ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ org.eclipse.jetty │ jetty-server    │ 9.4.48  │
│ com.fasterxml...  │ jackson-databind│ 2.13.4  │
│ org.apache.avro   │ avro            │ 1.8.2   │
...

Dependencies exported to: dependencies.json
```

### 2.3 Check Status

```bash
# View current database status
python main.py status
```

## Phase 3: Test Run (Dry Run Equivalent)

Before running full remediation, let's test individual components:

### 3.1 Test Database

```python
# Create test script: test_db.py
from src.storage.database import CVEDatabase

db = CVEDatabase("./data/spark_cve.db")

# Insert test CVE
test_cve = {
    'cve_id': 'CVE-2024-TEST',
    'severity': 'HIGH',
    'title': 'Test Vulnerability',
    'description': 'Testing database',
    'affected_library': 'org.test:test',
    'current_version': '1.0.0',
    'fixed_version': '1.0.1',
    'cvss_score': 7.5
}

db.insert_cve(test_cve)
print("✅ Database working!")

# Get pending CVEs
pending = db.get_pending_cves(['HIGH'])
print(f"Found {len(pending)} pending CVEs")

db.close()
```

Run it:
```bash
python test_db.py
```

### 3.2 Test POM Parser

```python
# Create test script: test_pom.py
from src.tools.spark_tools import PomParser
import os

spark_path = os.getenv('SPARK_SOURCE_PATH')
parser = PomParser(spark_path)

deps, props = parser.extract_dependencies()
print(f"✅ Found {len(deps)} dependencies")

# Test updating a version (with backup)
success = parser.update_dependency_version(
    'org.slf4j',
    'slf4j-api',
    '1.7.36',
    backup=True
)

if success:
    print("✅ POM update successful")
else:
    print("⚠️  POM update failed (might not exist)")
```

Run it:
```bash
python test_pom.py
```

## Phase 4: First Remediation Run

### 4.1 Create a Test Branch (Recommended)

```bash
cd $SPARK_SOURCE_PATH
git checkout -b cve-remediation-test
git branch  # Verify you're on the test branch
```

### 4.2 Run Limited Remediation

For your first run, limit iterations:

```bash
# Edit .env temporarily
nano .env

# Change:
MAX_ITERATIONS=3  # Start with just 3 iterations
```

### 4.3 Run Remediation (Interactive)

```bash
python main.py remediate
```

**You'll see:**
```
╔═══════════════════════════════════════════════════════════╗
║                                                            ║
║        Apache Spark CVE Remediation Agent                 ║
║        Powered by GPT-4 & LangChain                       ║
║                                                            ║
╚═══════════════════════════════════════════════════════════╝

⚠️  This will modify your Spark source code and rebuild.
Make sure you have a backup or are working in a separate branch.

Continue? [y/N]: y
```

### 4.4 Monitor Progress

The agent will:
1. Run initial scan
2. Extract dependencies
3. For each iteration:
   - Consult GPT-4 for best action
   - Update POM file
   - Build Spark
   - Verify fix
   - Update database

**Example iteration output:**
```
============================================================
🔄 Starting Remediation Cycle 1
============================================================

📊 Pending CVEs: 45

🤔 Consulting AI agent for next action...

💡 Agent Decision:
   Action: upgrade
   Library: org.eclipse.jetty:jetty-server
   Version: 9.4.48 → 9.4.53
   Reasoning: Version 9.4.53 fixes 3 CRITICAL CVEs (CVE-2024-1234, 
              CVE-2024-5678, CVE-2024-9012) with minimal risk
   CVEs Targeted: 3

✏️  Updating POM file...
✅ Updated org.eclipse.jetty:jetty-server from 9.4.48 to 9.4.53

🔨 Building Spark...
✅ Build successful! Duration: 456.2s

🔍 Re-scanning for CVEs...

✅ CVEs Fixed: 3
   - CVE-2024-1234
   - CVE-2024-5678
   - CVE-2024-9012
```

### 4.5 Review Results

After completion:

```
============================================================
📊 Final Report
============================================================

     Remediation Summary      
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric             ┃ Value ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Initial CVEs       │ 45    │
│ Final CVEs         │ 32    │
│ CVEs Fixed         │ 13    │
│ Iterations         │ 3     │
│ Successful Upgr... │ 3     │
│ Failed Upgrades    │ 0     │
│ Skipped CVEs       │ 0     │
└────────────────────┴───────┘

Initial vs Final Severity Counts:
┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Initial ┃ Final ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━┩
│ CRITICAL │ 5       │ 2     │
│ HIGH     │ 15      │ 12    │
│ MEDIUM   │ 25      │ 18    │
└──────────┴─────────┴───────┘

Full report saved to: remediation_report.json

✅ Remediation process complete!
```

## Phase 5: Full Production Run

After successful test:

### 5.1 Review Test Results

```bash
# Check what was changed
cd $SPARK_SOURCE_PATH
git diff main..cve-remediation-test pom.xml

# Review build logs
ls -lh ~/spark-cve-agent/logs/

# Check database
python main.py status
```

### 5.2 Prepare for Full Run

```bash
# Increase max iterations
nano .env
# Set: MAX_ITERATIONS=50

# Create production branch
git checkout -b cve-remediation-prod
```

### 5.3 Run Full Remediation

```bash
cd ~/spark-cve-agent
source venv/bin/activate
python main.py remediate --yes --report production_report.json
```

This will run until:
- All CRITICAL/HIGH CVEs are fixed
- OR max iterations reached
- OR all remaining CVEs are unfixable

### 5.4 Final Verification

```bash
# Run final scan
python main.py scan --output final_scan.json

# Compare with initial
python << 'EOF'
import json

with open('data/scans/initial_scan.json') as f:
    initial = json.load(f)

with open('final_scan.json') as f:
    final = json.load(f)

print(f"Initial: {initial['total_cves']} CVEs")
print(f"Final: {final['total_cves']} CVEs")
print(f"Fixed: {initial['total_cves'] - final['total_cves']} CVEs")
EOF
```

## Common Scenarios & Solutions

### Scenario 1: Build Fails After Upgrade

**What happens:**
```
❌ Build failed!

🔍 Analyzing build failure...

📋 Failure Analysis:
   Action: incremental
   Reasoning: The version jump from 9.4.48 to 9.4.53 introduced 
              API incompatibilities. Suggest trying 9.4.51 first.
   Suggested Version: 9.4.51
```

**The agent will:**
1. Automatically try the suggested intermediate version
2. If that fails, may rollback
3. Mark CVEs as skipped if truly unfixable

### Scenario 2: Dependency Conflicts

**What happens:**
```
📋 Failure Analysis:
   Action: dependency_conflict
   Reasoning: Jetty 10.x requires Jakarta EE but Spark uses Java EE.
              This is a major upgrade requiring code changes.
   Conflicting Dependencies: javax.servlet:javax.servlet-api
```

**The agent will:**
1. Skip these CVEs
2. Mark them as requiring manual intervention
3. Document in final report

### Scenario 3: Library Already at Latest

**What happens:**
```
💡 Agent Decision:
   Action: skip
   Reasoning: org.apache.commons:commons-text is already at latest 
              version 1.10.0. CVE-2024-XXXX requires code changes.
   CVEs Skipped: [CVE-2024-XXXX]
```

## Tips & Best Practices

### 1. Start Small
- First run: `MAX_ITERATIONS=3`
- Test on single library upgrade
- Verify builds work

### 2. Use Git Branches
```bash
git checkout -b cve-fix-$(date +%Y%m%d)
# Run remediation
# Review changes
git diff main pom.xml
```

### 3. Monitor Builds
```bash
# Tail build log in another terminal
tail -f logs/build_*.log
```

### 4. Save Reports
```bash
# Create dated reports
python main.py remediate --report reports/report_$(date +%Y%m%d).json
```

### 5. Backup Before Major Runs
```bash
# Backup your Spark source
tar -czf spark_backup_$(date +%Y%m%d).tar.gz $SPARK_SOURCE_PATH
```

## Troubleshooting

### Issue: "No module named 'src'"

**Solution:**
```bash
# Make sure you're in the project root
cd ~/spark-cve-agent
# And virtual environment is activated
source venv/bin/activate
```

### Issue: "OpenAI rate limit exceeded"

**Solution:**
```bash
# Add delay between iterations
# Edit src/agents/cve_agent.py, add after each LLM call:
import time
time.sleep(20)  # 20 second delay
```

### Issue: Build takes too long

**Solution:**
```bash
# Increase timeout in src/tools/spark_tools.py:
timeout=3600  # Change to 7200 (2 hours)
```

## Next Steps

After successful remediation:

1. **Review All Changes**
   ```bash
   git diff main pom.xml
   ```

2. **Run Spark Tests**
   ```bash
   cd $SPARK_SOURCE_PATH
   mvn test -pl core
   ```

3. **Create Pull Request**
   ```bash
   git add pom.xml
   git commit -m "fix: remediate CRITICAL and HIGH CVEs"
   git push origin cve-remediation
   ```

4. **Document Unfixed CVEs**
   - Review `remediation_report.json`
   - Document why certain CVEs couldn't be fixed
   - Create tickets for manual fixes

## Advanced Usage

### Custom Prompts

Edit system prompt in `src/agents/cve_agent.py`:

```python
def create_system_prompt(self) -> str:
    return """You are an expert CVE remediation specialist...
    
    [Add custom instructions here]
    """
```

### Integration with CI/CD

```bash
# Run as part of CI
python main.py scan --severity CRITICAL,HIGH || exit 1

# Automatic remediation (careful!)
python main.py remediate --yes
```

### Custom Reports

```python
# Create custom report analyzer
import json

with open('remediation_report.json') as f:
    report = json.load(f)

# Your custom analysis
critical_fixed = report['initial_severity_counts']['CRITICAL'] - \
                report['final_severity_counts']['CRITICAL']

print(f"🎯 {critical_fixed} CRITICAL CVEs fixed!")
```

---

**Questions?** Check README.md or logs in `./logs/`

**Happy Remediating! 🚀**
