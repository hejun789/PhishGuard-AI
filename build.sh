#!/usr/bin/env bash
# Render build script — generates dataset and trains model
set -e
echo "=== Installing dependencies ==="
pip install -r requirements.txt

echo "=== Generating dataset ==="
python data/generate_dataset.py

echo "=== Training models ==="
python models/train_models.py

echo "=== Build complete ==="
