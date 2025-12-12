# MalCluster

**MalCluster** is a pipeline for extracting static analysis artifacts from malware samples using the **Malcat Python API**, with a **Flask-based web GUI** for interactive usage.

<div align="center" style="display:flex; justify-content:center; gap:20px;">
  <img src="media/home.gif" width="700" />
  <img src="media/clusters.gif" width="700" />
</div>

## Installation
```bash
git clone https://github.com/federicofantini/malcluster.git
cd malcluster
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 app.py
```

## Features
Interactive GUI built with Flask + Vis Network JS for:
  - Uploading malware samples
  - Configuring pipeline parameters
  - Viewing similarity clusters visually and interactively

The pipeline performs the following steps:
- Extracts **printable strings** and raw disassembly from a binary sample.
- Normalizes disassembly by replacing registers, immediates, and memory references with generic placeholders.
- Stores all artifacts in a **single JSON file**:
  - `string_data`: printable strings with frequency statistics
  - `functions`: raw disassembly per function
  - `normalized_functions`: abstracted/normalized disassembly
- Generates a **similarity graph** of clustered samples using three similarity functions:
  - `ssdeep`
  - `tlsh`
  - `sdhash`

## Demo Video
A demo video is available at [`demo.mp4`](media/demo.mp4), showcasing:
- Uploading malware samples  
- Setting pipeline parameters  
- Running the analysis  
- Interactive graph visualization  
