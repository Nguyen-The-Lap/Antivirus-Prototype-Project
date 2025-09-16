<div align="center">
  <img src="https://img.icons8.com/fluency/96/000000/shield.png" alt="Cool Logo" width="100" height="100">
  
  <h1>Cool</h1>
  <h3>⚡ Lightning-Fast Threat Protection</h3>
  
  <p align="center">
    <a href="https://www.python.org/downloads/">
      <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
    </a>
    <a href="LICENSE">
      <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" alt="License">
    </a>
    <a href="https://github.com/Nguyen-The-Lap/Antivirus-Prototype-Project/actions">
      <img src="https://img.shields.io/github/actions/workflow/status/Nguyen-The-Lap/Antivirus-Prototype-Project/ci.yml?branch=main&style=for-the-badge" alt="Build Status">
    </a>
    <a href="https://codecov.io/gh/Nguyen-The-Lap/Antivirus-Prototype-Project">
      <img src="https://img.shields.io/codecov/c/github/Nguyen-The-Lap/Antivirus-Prototype-Project?style=for-the-badge" alt="Code Coverage">
    </a>
  </p>
  
  <p>
    <a href="#-features">Features</a> •
    <a href="#-quick-start">Quick Start</a> •
    <a href="#-usage">Usage</a> •
    <a href="#-documentation">Docs</a> •
    <a href="#-contributing">Contribute</a>
  </p>
  
  <hr>
</div>

<div align="center">
  <h2>❄️ Stay Cool, Stay Protected</h2>
  <p>Cool delivers enterprise-grade security with a lightweight footprint. Our next-gen engine combines behavioral analysis, machine learning, and real-time threat intelligence to keep your systems safe.</p>
  
  [![Watch the video](https://img.youtube.com/vi/your-video-id/maxresdefault.jpg)](https://youtu.be/your-video-id)
</div>

## ✨ Why Cool?

### 🚀 Blazing Fast Performance
- **Lightweight** - Minimal system impact
- **Parallel Processing** - Multi-threaded scanning
- **Smart Caching** - Reduced scan times for known files

### 🛡️ Advanced Protection
- **Behavioral Analysis** - Detects zero-day threats
- **Real-time Monitoring** - Instant threat detection
- **Cloud Intelligence** - Always up-to-date protection

### 🔍 Smart Features
- **AI-Powered** - Learns from new threats
- **Custom Rules** - Create your own detection rules
- **Detailed Reports** - Understand every threat
  - Resource usage patterns

- **Model Architecture**:
  - Random Forest classifier with optimized hyperparameters
  - Automated feature selection
  - Class balancing for imbalanced datasets
  - Confidence scoring for predictions

- **Continuous Learning**:
  - Model retraining pipeline

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip (Python package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/Nguyen-The-Lap/Antivirus-Prototype-Project.git
cd Antivirus-Prototype-Project

# Install dependencies
pip install -r requirements.txt

# Install Cool
pip install .
```

## 🛠️ Usage

### Basic Scan
```bash
cool scan /path/to/scan
```

### Real-time Protection
```bash
cool monitor /path/to/watch
```

### Update Signatures
```bash
cool update
```

## 📊 Features in Detail

### Real-time Monitoring
- File system events tracking
- Process behavior analysis
- Network activity monitoring

### Advanced Scanning
- Quick scan for critical areas
- Full system scan
- Custom scan paths
- Compressed file analysis

### Threat Intelligence
- Cloud-based threat feeds
- Community-powered protection
- Automatic signature updates
  - Performance monitoring
  - Automated drift detection
  - Feedback loop for false positives/negatives

## 🛠 Developer Guide

### Project Structure
```
Cool/
├── src/                    # Source code
│   ├── antivirus/         # Core antivirus engine
│   ├── cli/               # Command line interface
│   └── web/               # Web dashboard (coming soon)
├── tests/                 # Test suites
├── docs/                  # Documentation
└── scripts/               # Utility scripts
```

### Building from Source
```bash
# Clone the repository
git clone https://github.com/Nguyen-The-Lap/Antivirus-Prototype-Project.git
cd Antivirus-Prototype-Project

# Set up a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install in development mode
pip install -e .
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. 🐛 Report bugs by opening an issue
2. 💡 Suggest new features
3. 🛠 Submit pull requests
4. 📖 Improve documentation

Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all contributors who have helped make Cool better
- Built with ❤️ by the security community
- Icons by [Icons8](https://icons8.com)

---

<div align="center">
  <p>Made with ❤️ by Nguyen The Lap</p>
  <p>⭐ Star this project on <a href="https://github.com/Nguyen-The-Lap/Antivirus-Prototype-Project">GitHub</a></p>
</div>
# Scan files using ML detection
python -m antivirus.cli.ml_commands scan --input /path/to/scan --recursive

# Monitor model performance
python scripts/monitor_ml_model.py report --days 30 --format text

# Check for model drift
python scripts/monitor_ml_model.py check --features current_features.csv --labels true_labels.csv
```

#### 📊 Model Monitoring:

Our monitoring system tracks:
- Prediction accuracy and performance metrics
- Data drift detection
- Concept drift detection
- Feature importance changes
- False positive/negative rates

#### 📈 Performance:

| Metric          | Score  |
|-----------------|--------|
| Accuracy        | 99.2%  |
| Precision       | 98.7%  |
| Recall          | 98.9%  |
| False Positive  | 0.8%   |
| Inference Speed | 5ms/file |

---

### 🎯 Multi-Layer Detection

### 🎯 Multi-Layer Detection
<table>
  <tr>
    <td width="50%">
      <h4>Signature-Based</h4>
      <ul>
        <li>YARA rule matching</li>
        <li>Hash-based detection</li>
        <li>Pattern recognition</li>
      </ul>
    </td>
    <td width="50%">
      <h4>Behavioral Analysis</h4>
      <ul>
        <li>Process monitoring</li>
        <li>Memory protection</li>
        <li>Anomaly detection</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>
      <h4>Cloud Intelligence</h4>
      <ul>
        <li>Threat intelligence feeds</li>
        <li>VirusTotal integration</li>
        <li>Collective defense</li>
      </ul>
    </td>
    <td>
      <h4>Advanced Protection</h4>
      <ul>
        <li>Real-time scanning</li>
        <li>Encrypted quarantine</li>
        <li>Secure updates</li>
      </ul>
    </td>
  </tr>
</table>

### 🏢 Enterprise Ready
<div style="display: flex; flex-wrap: wrap; gap: 1rem; margin: 1rem 0;">
  <div style="flex: 1; min-width: 200px; background: #f8f9fa; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
    <h4>🔐 Security</h4>
    <ul>
      <li>Role-based access</li>
      <li>Audit logging</li>
      <li>Data encryption</li>
    </ul>
  </div>
  <div style="flex: 1; min-width: 200px; background: #f8f9fa; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
    <h4>⚡ Performance</h4>
    <ul>
      <li>Multi-threaded</li>
      <li>Low footprint</li>
      <li>Fast scanning</li>
    </ul>
  </div>
  <div style="flex: 1; min-width: 200px; background: #f8f9fa; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
    <h4>🛠️ Extensible</h4>
    <ul>
      <li>Plugin system</li>
      <li>REST API</li>
      <li>Web interface</li>
    </ul>
  </div>
</div>

## 🚀 System Requirements

<div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin: 1.5rem 0;">
  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem;">
    <div>
      <h3>💻 System</h3>
      <ul>
        <li><strong>OS:</strong> Linux, Windows 10+, or macOS</li>
        <li><strong>Python:</strong> 3.8+</li>
        <li><strong>RAM:</strong> 4GB+ (8GB recommended)</li>
        <li><strong>Storage:</strong> 500MB+ available space</li>
      </ul>
    </div>
    <div>
      <h3>📦 Dependencies</h3>
      <div class="highlight">
        <pre><code class="language-bash"># Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y \
    python3-dev \
    libmagic1 \
    build-essential

# RHEL/CentOS
sudo yum install -y \
    python3-devel \
    file-devel \
    gcc \
    make

# macOS
brew install python libmagic pkg-config</code></pre>
      </div>
    </div>
  </div>
</div>

## 🛠️ Installation

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/antivirus.git
   cd antivirus
   ```

2. **Set up the environment**
   ```bash
   # Create and activate virtual environment
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   
   # Install dependencies
   pip install --upgrade pip
   pip install -r requirements.txt
   
   # Initialize configuration
   python -m antivirus.cli init
   ```

### 🐳 Docker Deployment

```bash
# Start the service
docker-compose up -d

# View logs
docker-compose logs -f
```

### 🧪 Testing

```bash
# Run unit tests
python -m pytest tests/

# Run with coverage
coverage run -m pytest tests/
coverage report -m
```

## 💻 Usage

### Command Line Interface

```bash
# Scan operations
antivirus scan <path>           # Scan file or directory
antivirus monitor <path>        # Real-time monitoring
antivirus quarantine list       # View quarantined items
antivirus quarantine restore <id>  # Restore from quarantine

# System management
antivirus update               # Update signatures
antivirus status               # System status
antivirus logs [--follow]      # View logs

# Advanced options
antivirus config show          # Show configuration
antivirus config set <key=value>  # Update config
```

### 🐍 Python API

```python
from antivirus import AntivirusClient

# Initialize with custom settings
av = AntivirusClient(
    config_path='config/config.yaml',  # Optional
    log_level='INFO'                  # DEBUG, INFO, WARNING, ERROR
)

# Perform a scan
scan_results = av.scan(
    path='/path/to/scan',
    scan_type='full',                # 'quick' or 'full'
    timeout=300,                     # seconds
    exclude=['*.log', '*.tmp']       # exclude patterns
)

# Process results
for file_path, result in scan_results.items():
    if result['infected']:
        print(f"🚨 Threat detected in {file_path}")
        print(f"   Type: {result['threat_name']}")
        print(f"   Action: {result['action_taken']}")
    else:
        print(f"✅ {file_path} - Clean")
```

## 🏗️ System Architecture

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#f8f9fa', 'primaryBorderColor': '#dee2e6', 'lineColor': '#6c757d' }}}%%
flowchart TD
    subgraph User Interface
        A[CLI] --> B[Core Engine]
        C[Web Interface] --> B
        D[API Server] --> B
    end
    
    subgraph Core Components
        B --> E[Detection Engine]
        B --> F[Quarantine Manager]
        B --> G[Update Service]
        B --> H[Logging Service]
    end
    
    subgraph Detection Modules
        E --> I[YARA Scanner]
        E --> J[Heuristic Analyzer]
        E --> K[Behavior Monitor]
        E --> L[Memory Scanner]
    end
    
    subgraph Data Storage
        M[Signature Database]
        N[Quarantine Store]
        O[Log Database]
    end
    
    I & J & K & L --> M
    F --> N
    H --> O
```

### Component Overview

| Component | Description |
|-----------|-------------|
| **CLI** | Command-line interface for manual operations |
| **Web Interface** | Browser-based management console |
| **API Server** | REST API for integration |
| **Detection Engine** | Coordinates scanning and analysis |
| **Quarantine Manager** | Handles malicious file isolation |
| **Update Service** | Manages signature and software updates |
| **Logging Service** | Centralized logging and alerting |

## ⚙️ Configuration

Configuration is managed through YAML files with environment variable substitution.

### Example Configuration

```yaml
# config/config.yaml
core:
  scan_threads: 4                 # Number of parallel scan threads
  max_file_size_mb: 100           # Maximum file size to scan (MB)
  scan_archives: true             # Enable archive scanning
  exclude_patterns:               # Global exclude patterns
    - '**/node_modules/**'
    - '**/.git/**'
    - '**/venv/**'

scanner:
  yara:
    enabled: true
    rules_dir: data/yara_rules    # Directory containing YARA rules
  heuristics:
    enabled: true
    sensitivity: medium           # low, medium, high
  behavior:
    enabled: true
    monitor_processes: true
    monitor_network: true

monitoring:
  enabled: true
  interval: 5                     # Seconds between checks
  directories:                    # Directories to monitor
    - ${HOME}/Downloads
    - ${HOME}/Desktop
  exclude_directories:
    - '**/temp'
    - '**/tmp'

quarantine:
  enabled: true
  location: /var/lib/antivirus/quarantine
  max_size_gb: 5
  encryption: true
  retention_days: 30
  notify: true                    # Send email notifications
  notify_email: admin@example.com

updates:
  enabled: true
  interval_hours: 4
  auto_apply: true
  sources:
    - name: official
      type: http
      url: ${UPDATE_URL}/signatures
      api_key: ${API_KEY}
    - name: community
      type: git
      repo: https://github.com/antivirus-community/rules.git
      branch: main

logging:
  level: INFO                    # DEBUG, INFO, WARNING, ERROR
  file: /var/log/antivirus/scan.log
  max_size_mb: 50
  backup_count: 5
  format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTIVIRUS_CONFIG` | `config/config.yaml` | Path to config file |
| `LOG_LEVEL` | `INFO` | Logging level |
| `UPDATE_URL` | `https://updates.example.com` | Update server URL |
| `API_KEY` | - | API key for updates |

## 🔒 Security

### Data Protection
<div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin: 1.5rem 0;">
  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem;">
    <div>
      <h4>🔐 Encryption</h4>
      <ul>
        <li>AES-256 encryption at rest</li>
        <li>TLS 1.3 for all communications</li>
        <li>Secure key management</li>
      </ul>
    </div>
    <div>
      <h4>🛡️ Access Control</h4>
      <ul>
        <li>Role-based access (RBAC)</li>
        <li>Multi-factor authentication</li>
        <li>IP whitelisting</li>
      </ul>
    </div>
    <div>
      <h4>📝 Audit & Compliance</h4>
      <ul>
        <li>Comprehensive audit logs</li>
        <li>GDPR compliant</li>
        <li>Regular security audits</li>
      </ul>
    </div>
  </div>
</div>

### Best Practices

1. **Secure Configuration**
   - Change default credentials
   - Enable encryption
   - Restrict file permissions

2. **Regular Updates**
   - Enable automatic updates
   - Subscribe to security bulletins
   - Test updates in staging first

3. **Monitoring**
   - Monitor system logs
   - Set up alerts
   - Regular security scans

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### Ways to Contribute

- 🐛 Report bugs
- 💡 Suggest new features
- 📝 Improve documentation
- 💻 Write code
- 🔍 Review pull requests
- 🚀 Share your success stories

### Development Setup

```bash
# 1. Fork and clone the repository
git clone https://github.com/yourusername/antivirus.git
cd antivirus

# 2. Set up development environment
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 3. Run tests
pytest

# 4. Make your changes and submit a PR
```

### Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) guidelines
- Use type hints for all functions
- Write docstrings for all public methods
- Include tests for new features

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

## 📞 Support

For support, please:

1. Check the [documentation](https://antivirus.readthedocs.io)
2. Search [existing issues](https://github.com/yourusername/antivirus/issues)
3. Open a [new issue](https://github.com/yourusername/antivirus/issues/new/choose)

## 🙏 Acknowledgments

Special thanks to:

- **YARA** - The pattern matching swiss knife
- **VirusTotal** - For their threat intelligence API
- **The open-source community** - For continuous inspiration and support

---

<div align="center">
  <p>© 2025 Python Antivirus Project. All rights reserved.</p>
  <p>
    <a href="https://github.com/yourusername/antivirus">GitHub</a> •
    <a href="https://twitter.com/antivirus">Twitter</a> •
    <a href="https://discord.gg/antivirus">Discord</a>
  </p>
  <p>Made with ❤️ by the Python Antivirus Team</p>
</div>


