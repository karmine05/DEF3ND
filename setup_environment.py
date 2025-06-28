#!/usr/bin/env python3
"""
Environment Setup Script for SIGMA Detection Engineering Platform
Creates conda environment and installs dependencies
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(command, description=""):
    """Run a shell command and handle errors"""
    print(f"\n{'='*60}")
    print(f"🔧 {description}")
    print(f"Command: {command}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ Success: {description}")
        if result.stdout:
            print(f"Output: {result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {description}")
        print(f"Error code: {e.returncode}")
        print(f"Error output: {e.stderr}")
        return False

def check_conda():
    """Check if conda is installed"""
    try:
        result = subprocess.run("conda --version", shell=True, check=True, capture_output=True, text=True)
        print(f"✅ Conda found: {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError:
        print("❌ Conda not found. Please install Anaconda or Miniconda first.")
        print("Download from: https://docs.conda.io/en/latest/miniconda.html")
        return False

def create_conda_environment():
    """Create the DET3CT conda environment"""
    print("\n🚀 Setting up SIGMA Detection Engineering Platform")
    print("=" * 60)
    
    # Check if conda is available
    if not check_conda():
        return False
    
    # Check if environment already exists
    try:
        result = subprocess.run("conda env list", shell=True, check=True, capture_output=True, text=True)
        if "DET3CT" in result.stdout:
            print("⚠️  DET3CT environment already exists.")
            response = input("Do you want to remove and recreate it? (y/N): ")
            if response.lower() == 'y':
                if not run_command("conda env remove -n DET3CT -y", "Removing existing DET3CT environment"):
                    return False
            else:
                print("Using existing environment...")
                return True
    except subprocess.CalledProcessError:
        pass
    
    # Create new environment with Python 3.11
    if not run_command("conda create -n DET3CT python=3.11 -y", "Creating DET3CT conda environment"):
        return False
    
    # Install packages from requirements.txt using conda run
    requirements_file = Path(__file__).parent / "requirements.txt"
    if requirements_file.exists():
        install_cmd = f"conda run -n DET3CT pip install -r {requirements_file}"
        if not run_command(install_cmd, "Installing Python packages"):
            return False
    else:
        print("⚠️  requirements.txt not found. Installing core packages...")
        core_packages = [
            "streamlit==1.29.0",
            "pandas==2.1.4",
            "numpy==1.24.3",
            "requests==2.31.0",
            "pyyaml==6.0.1",
            "ollama==0.1.7",
            "sentence-transformers==2.2.2",
            "plotly==5.17.0",
            "networkx==3.2.1",
            "stix2==3.0.1"
        ]

        for package in core_packages:
            install_cmd = f"conda run -n DET3CT pip install {package}"
            if not run_command(install_cmd, f"Installing {package}"):
                print(f"⚠️  Failed to install {package}, continuing...")
    
    print("\n🎉 Environment setup completed!")
    print("\nTo activate the environment, run:")
    print("conda activate DET3CT")
    print("\nTo start the application, run:")
    print("streamlit run app.py")
    
    return True

def setup_directories():
    """Create necessary directories"""
    directories = [
        "data/mitre_data",
        "data/sigma_rules", 
        "data/database",
        "logs"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def create_launch_script():
    """Create a launch script for easy startup"""
    launch_script = """#!/bin/bash
# SIGMA Detection Engineering Platform Launch Script

echo "🛡️  Starting SIGMA Detection Engineering Platform..."
echo "=" * 60

# Activate conda environment
source $(conda info --base)/etc/profile.d/conda.sh
conda activate DET3CT

# Check if Ollama is running
if ! pgrep -x "ollama" > /dev/null; then
    echo "⚠️  Ollama not detected. Please start Ollama first:"
    echo "   ollama serve"
    echo ""
fi

# Start Streamlit app
echo "🚀 Launching Streamlit application..."
streamlit run app.py --server.port 8501 --server.address localhost

echo "✅ Application started at http://localhost:8501"
"""
    
    with open("launch.sh", "w") as f:
        f.write(launch_script)
    
    # Make executable
    os.chmod("launch.sh", 0o755)
    print("✅ Created launch script: launch.sh")

def main():
    """Main setup function"""
    print("🛡️  SIGMA Detection Engineering Platform Setup")
    print("=" * 60)
    
    # Setup directories
    setup_directories()
    
    # Create conda environment
    if create_conda_environment():
        print("\n✅ Environment setup successful!")
    else:
        print("\n❌ Environment setup failed!")
        sys.exit(1)
    
    # Create launch script
    create_launch_script()
    
    print("\n🎉 Setup completed successfully!")
    print("\nNext steps:")
    print("1. Activate the environment: conda activate DET3CT")
    print("2. Start Ollama (if not running): ollama serve")
    print("3. Launch the application: ./launch.sh or streamlit run app.py")
    print("\n📚 Documentation and examples will be available in the web interface.")

if __name__ == "__main__":
    main()
