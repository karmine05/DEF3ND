#!/bin/bash
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
