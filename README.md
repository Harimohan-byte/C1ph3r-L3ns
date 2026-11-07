# CIPHER LENS

Local-first VAPT assessment assistant for explicitly authorized lab targets only.

## Phase 1 quick start

1. Create and activate a Python 3.12 virtual environment.
2. Install dependencies: `python -m pip install -r requirements.txt`.
3. Start the local workspace: `streamlit run src/cipher_lens/app.py`.
4. Run safety and persistence tests: `python -m pytest`.

The application stores its local SQLite database and raw evidence under `data/` by default. Set
`CIPHER_LENS_DATA_DIR` in an untracked `.env` file to change that location.
