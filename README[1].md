# Password Strength Analyzer – Web Version

Python + Streamlit web version of the Password Strength Analyzer.

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Deploy

Upload `app.py` and `requirements.txt` to a GitHub repository and deploy the repository using Streamlit Community Cloud.

The web version keeps the original analyzer logic and provides Check Password, Show/Hide, Copy, Clear, Breach Check, Strength, Score, Entropy, Crack Time, Suggestions, Password Analysis, Export Report and Reset.

**Breach Check note:** the current project checks against the same local common-password list used by the original Python project; it is not an online leaked-password database.
