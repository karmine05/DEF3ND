# 🛡️ SIGMA Detection Engineering Platform

A comprehensive, detection engineering platform that empowers security teams with advanced MITRE ATT&CK exploration, AI-powered SIGMA rule building, and sophisticated attack path visualization capabilities.

## 🎯 Platform Overview

The SIGMA Detection Engineering Platform is designed for security engineers, threat hunters, and detection teams who need to:

- **Explore and Understand** the MITRE ATT&CK framework comprehensively
- **Build and Manage** SIGMA detection rules with AI assistance
- **Visualize Attack Paths** and assess detection coverage
- **Search and Analyze** detection rules across multiple repositories

Built with scalability, performance, and production deployment in mind, this platform integrates seamlessly with existing security workflows while providing cutting-edge AI capabilities through local LLM integration.

## ✨ Features

### 🎯 Enhanced MITRE ATT&CK Explorer
- **Comprehensive Technique Browser**: Browse and search all MITRE ATT&CK techniques
- **Advanced Filtering**: Filter by tactics, platforms, data sources, and more
- **Enhanced Technique Detail View**: Complete MITRE data without truncation
- **AI-Enhanced Analysis**: Comprehensive technical analysis with threat intelligence
- **Detection Recommendations**: Specific guidance for building detection rules
- **Attack Scenarios**: Real-world attack implementations and contexts
- **Interactive Relationships**: Explore technique relationships and mappings
- **Coverage Analysis**: See detection rule coverage for each technique

#### 📋 Complete MITRE ATT&CK Data Section
- **Full Technique Information**: All available MITRE fields without truncation
- **Technical Details**: Platforms, permissions, data sources, system requirements
- **Detection & Mitigation**: Complete detection methods and mitigation strategies
- **References**: All external references and documentation links
- **Sub-techniques**: Related sub-techniques and procedure examples

#### 🤖 AI-Enhanced Technical Analysis Section
- **Threat Actor Usage Patterns**: Real-world usage by known threat groups
- **Technical Implementation**: How attackers execute the technique
- **Attack Chain Context**: Integration with other MITRE techniques
- **Detection Engineering Recommendations**: Specific detection strategies
- **Defense Strategies**: Preventive controls and monitoring best practices
- **False Positive Considerations**: Guidance for reducing alert fatigue

### 📝 SIGMA Rule Builder
- **Intelligent Rule Creation**: Create and edit SIGMA detection rules with LLM assistance
- **Rule Validation**: Built-in validation and syntax checking
- **Custom Management**: Organize rules with tags, categories, and metadata
- **Export Capabilities**: Export rules in multiple formats
- **Template Library**: Pre-built templates for common detection scenarios

### 🔍 Advanced Detection Search Engine
- **Multi-Modal Search**: Keyword and semantic search capabilities
- **Comprehensive Filtering**: Filter by tactics, platforms, severity, and custom criteria
- **Real-Time Results**: Fast, responsive search with live filtering
- **Export & Reporting**: Export search results for analysis and reporting
- **Search History**: Track and revisit previous searches

### 🗺️ Enhanced Attack Path Mapper
- **Full-Screen Visualizations**: Immersive, full-screen attack path visualizations
- **Multiple Layout Types**: Mind map, linear flow, hierarchical, and network graph views
- **Interactive Controls**: Zoom, pan, drag, and enhanced navigation
- **Enhanced Mode**: Advanced styling, animations, and interactive features
- **Keyboard Shortcuts**: ESC to close, F for browser full-screen, mouse wheel zoom
- **Attack Scenario Generation**: Generate realistic attack paths based on MITRE tactics
- **Coverage Analysis**: Real-time analysis of detection rule coverage
- **Export Capabilities**: Save visualizations and analysis reports

### ⚙️ Data Management
- **Automated Synchronization**: Weekly auto-sync of SIGMA rules from GitHub
- **MITRE Data Updates**: Automatic updates of MITRE ATT&CK framework data
- **Database Management**: SQLite with backup, optimization, and maintenance tools
- **Custom Content**: Support for custom rules and attack scenarios
- **Data Integrity**: Deduplication and validation of all imported data

## 🚀 Installation & Setup

### Prerequisites
- **Python 3.11+** (Required)
- **Anaconda or Miniconda** (Recommended)
- **Ollama** (Optional, for LLM features)
- **Modern Web Browser** (Chrome, Firefox, Safari, Edge)

### Quick Start

1. **Clone and Setup:**
```bash
git clone <repository-url>
cd SIGMA_CH_Builder
python setup_environment.py
```

2. **Create/Activate Environment:**
```bash
conda create -n DET3CT python=3.11
conda activate DET3CT
```

3. **Configure Environment (Optional):**
```bash
cp .env.example .env
# Edit .env file with your preferred settings
```

4. **Start Ollama (Optional for AI features):**
```bash
ollama serve
ollama pull qwen2.5:7b  # or your preferred model
```

5. **Launch Application:**
```bash
./launch.sh
# or manually: streamlit run app.py
```

6. **Access Platform:**
Open `http://localhost:8501` in your browser

### Initial Configuration

1. **Navigate to Settings & Sync**
2. **Update MITRE Data** - Download latest MITRE ATT&CK techniques
3. **Sync SIGMA Rules** - Download detection rules from repositories
4. **Configure LLM** - Set up Ollama connection (optional)
5. **Test Features** - Verify all components are working

## 🎮 Usage Guide

### Enhanced MITRE Technique Analysis

The platform provides comprehensive technique analysis in two distinct sections:

#### 📋 Accessing Complete Technique Details
1. **Navigate to MITRE ATT&CK Explorer**
2. **Browse or Search** for techniques using filters (tactic, platform, data source)
3. **Click "📋 View Complete Details"** on any technique card
4. **Explore Four Analysis Tabs**:
   - **Complete MITRE Data**: Untruncated framework information
   - **AI Analysis**: Comprehensive technical analysis
   - **Detection Recommendations**: Specific detection guidance
   - **Attack Scenarios**: Real-world implementation examples

#### 🤖 AI-Enhanced Analysis Features
- **Threat Actor Patterns**: Understanding how real threat groups use techniques
- **Technical Implementation**: Detailed execution methods and prerequisites
- **Attack Chain Context**: How techniques connect to broader attack sequences
- **Detection Engineering**: Specific strategies for building effective detections
- **Defense Strategies**: Preventive controls and monitoring recommendations
- **False Positive Guidance**: Reducing alert fatigue with context-aware detection

### Full-Screen Visualizations

The platform features enhanced full-screen visualization capabilities:

- **Access**: Click the "🔍 Full Screen" button on any visualization
- **Navigation**: Use mouse wheel to zoom, drag to pan
- **Keyboard Shortcuts**:
  - `ESC` - Close full-screen view
  - `F` - Toggle browser full-screen mode
  - Mouse wheel - Zoom in/out
- **Enhanced Mode**: Toggle for advanced styling and animations
- **Layout Options**: Choose between Mind Map, Linear Flow, Hierarchical, or Network Graph

## 🏗️ Architecture

### System Components
- **Frontend**: Streamlit web interface with responsive design
- **Backend**: Python with SQLite database
- **LLM Integration**: Ollama for AI-powered features
- **Visualization**: Enhanced full-screen capabilities with multiple layout types
- **Data Sources**: MITRE ATT&CK, SIGMA rule repositories

### Code Architecture
- **Centralized Database Operations**: All database access through `DatabaseManager.get_connection()`
- **Consolidated Functions**: Eliminated redundant functions across modules
- **Unified Validation**: Centralized validation methods in `DatabaseManager`
- **Modular Design**: Clean separation of concerns across components
- **Production-Ready**: Optimized, scalable code with comprehensive error handling

### Data Pipeline
1. **Automated Sync**: Weekly synchronization from official sources
2. **Data Processing**: Validation, deduplication, and normalization
3. **Relationship Mapping**: Automatic mapping between rules and techniques
4. **Storage**: Optimized SQLite database with indexing
5. **Backup**: Automated backup and recovery capabilities

## 🔧 Configuration

### Environment Variables
All configuration can be customized via environment variables. See `.env.example` for complete options:

- **LLM Settings**: `OLLAMA_HOST`, `OLLAMA_MODEL`
- **Sync Settings**: `AUTO_SYNC_ENABLED`, `SYNC_INTERVAL_DAYS`
- **Performance**: `ENABLE_CACHING`, `CACHE_TTL_SECONDS`
- **Features**: `ENABLE_AI_FEATURES`, `ENABLE_SEMANTIC_SEARCH`

### Database Configuration
- **Location**: `data/database/sigma_platform.db`
- **Backups**: Automated backup system available
- **Optimization**: Automatic indexing and query optimization

### LLM Models (Supported)
- `qwen2.5:7b` (Recommended)
- `llama3:8b`
- `deepseek-r1:7b`
- Custom models via Ollama

## 🛠️ Maintenance

### Regular Tasks
- **Weekly**: Automatic SIGMA rule sync
- **Monthly**: MITRE ATT&CK data updates
- **As Needed**: Database optimization and cleanup

### Backup & Recovery
- **Automatic Backups**: Available through Settings interface
- **Manual Backup**: Use "Backup Database" button
- **Recovery**: Restore from backup files in `data/database/backups/`

## 🐛 Troubleshooting

### Common Issues

**Visualization Performance**:
- Reduce attack path complexity
- Use Enhanced Mode selectively
- Clear browser cache

**Database Issues**:
- Check file permissions in `data/` directory
- Verify SQLite installation
- Use backup/restore if corrupted

**LLM Connection**:
- Verify Ollama is running: `ollama ps`
- Check model availability: `ollama list`
- Test connection in Settings

**Sync Failures**:
- Check internet connectivity
- Verify GitHub repository access
- Review sync logs

## 🤝 Contributing

We welcome contributions! Please:

1. **Fork** the repository
2. **Create** a feature branch
3. **Implement** your changes
4. **Test** thoroughly
5. **Submit** a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **MITRE Corporation** for the ATT&CK framework
- **SigmaHQ Community** for detection rules and format
- **Ollama Project** for LLM integration capabilities
- **Streamlit Team** for the excellent web framework
- **Open Source Community** for various dependencies and tools

---

**Built for Security Teams, by Security Engineers**

*Empowering detection engineering with AI-powered tools and comprehensive threat intelligence.*

**Production Ready**: This platform is designed for production use with comprehensive error handling, logging, backup capabilities, performance optimization, and enterprise-grade features.