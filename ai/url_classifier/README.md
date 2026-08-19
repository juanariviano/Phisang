# Phisang URL classifier data pipeline

The preprocessing CLI converts the PhiUSIIL source dataset into a clean,
URL-only training CSV that matches Phisang's no-destination-fetch design. It
also produces Markdown and JSON EDA reports.

Run it from the repository root:

```powershell
.\backend\.venv\Scripts\python.exe -B ai\url_classifier\prepare_dataset.py
```

Default outputs:

- `datasets/processed/PhiUSIIL_url_only_clean.csv`
- `reports/PhiUSIIL_eda_report.md`
- `reports/PhiUSIIL_eda_summary.json`

The pipeline uses only the Python standard library. It:

1. Validates the source schema and labels.
2. Accepts only HTTP(S) URLs compatible with the backend's 4,096-character limit.
3. Normalizes scheme, hostname, IDNA, and default ports.
4. Removes URL credentials while retaining a binary userinfo signal.
5. Deduplicates normalized URLs and drops label conflicts.
6. Removes page-fetch fields, unique identifiers, and known label proxies.
7. Recomputes deterministic URL-string features.
8. Remaps the target to `is_phishing=1` and `is_phishing=0` for legitimate.

On Windows, close the generated CSV in Excel before rerunning the pipeline so
the atomic output replacement is not held by an application-level file lock.

The generated report documents strong collection bias in the source dataset.
Use a registered-domain-grouped split and an independent external test set;
do not use a random row split for model-performance claims.

## Model training notebook

Create and activate a project-local environment, then open the notebook:

```powershell
python -m venv ai\url_classifier\.venv
.\ai\url_classifier\.venv\Scripts\python.exe -m pip install -r ai\url_classifier\requirements-training.txt
.\ai\url_classifier\.venv\Scripts\python.exe -m ipykernel install --prefix ai\url_classifier\.venv --name phisang-url-classifier --display-name "Phisang URL Classifier (.venv)"
.\ai\url_classifier\.venv\Scripts\jupyter-lab.exe ai\url_classifier\train_url_classifier.ipynb
```

The notebook uses public-suffix-aware registered-domain groups, keeps the test
partition untouched until final evaluation, compares a logistic baseline with
histogram gradient boosting, calibrates the chosen model, locks a validation
threshold, and exports a versioned model bundle plus JSON metadata under
`artifacts/`.

## Model testing notebook

Open the tester with the same project-local environment:

```powershell
.\ai\url_classifier\.venv\Scripts\jupyter-lab.exe ai\url_classifier\test_url_classifier.ipynb
```

Use `URLS_TO_TEST` for pasted URLs. For a CSV, set `BATCH_INPUT_CSV` and
`BATCH_URL_COLUMN`; optionally set `BATCH_OUTPUT_CSV` to save predictions. An
independent labeled CSV can also set `BATCH_LABEL_COLUMN`, using
`is_phishing=1` and `is_phishing=0` for legitimate. The tester imports the
runtime normalizer and feature extractor from `prepare_dataset.py`, performs no
network requests, and records invalid inputs without aborting the batch.
