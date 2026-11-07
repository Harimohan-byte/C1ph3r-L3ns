# CIPHER LENS

Local-first VAPT assessment assistant for explicitly authorized lab targets only.

## Phase 1 quick start

1. Create and activate a Python 3.13 virtual environment: `py -3.13 -m venv .venv`.
2. Install dependencies: `.\.venv\Scripts\python -m pip install -r requirements.txt`.
3. Start the local workspace: `$env:PYTHONPATH = (Resolve-Path 'src').Path; .\.venv\Scripts\python -m streamlit run src/cipher_lens/app.py`.
4. Run safety and persistence tests: `$env:PYTHONPATH = (Resolve-Path 'src').Path; .\.venv\Scripts\python -m pytest`.

The application stores its local SQLite database and raw evidence under `data/` by default. Set
`CIPHER_LENS_DATA_DIR` in an untracked `.env` file to change that location.

If the standard virtual environment demonstrably fails on a host, install the same requirements
into a project-local `.python-packages` directory and set `PYTHONPATH` to it before running Python.
