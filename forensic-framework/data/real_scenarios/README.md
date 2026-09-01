# CERT-derived evaluation windows

This directory contains bounded, downsampled evaluation windows derived from
release 4.2 of Carnegie Mellon University's synthetic CERT Insider Threat Test
Dataset. The source dataset is published under the Creative Commons
Attribution 4.0 International license.

Source: <https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247>

The files here are processed research artifacts, not logs from real people or
organizations. The extraction parameters and selected windows are recorded in
`manifest.json`; the corresponding adapter and pipeline live in
`app/ingestion/adapters/cert_insider.py` and `run_cert_pipeline.py`.
