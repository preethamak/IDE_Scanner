# VS Code Credential Exposure Dataset

This directory is for normalized benchmark data derived from the public
replication package for "Protect Your Secrets: Understanding and Measuring Data
Exposure in VSCode Extensions".

Source repository:

https://github.com/yueyueL/VSCode-Extensions-Security-Analysis/

The public repository includes `data/Ground_Truth_datasets.csv`, a manually
labeled dataset of data points across 500 extensions. The larger vulnerability
dataset described by the paper is request-only, so this adapter supports both
the public CSV and future requested data once available.

Normalize the public CSV with:

```bash
python3 -m ide_scanner.benchmarks.adapters.protect_your_secrets \
  data/Ground_Truth_datasets.csv \
  benchmarks/datasets/vscode-credential-exposure/normalized.json
```
