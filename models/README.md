# models/

This folder is a placeholder for an optional trained scikit-learn
classifier (e.g. `phishing_model.pkl`) that could supplement the
rule-based risk engine in `backend/risk_engine.py`.

The current MVP intentionally ships **without** a trained model so it
runs end-to-end out of the box with zero setup. The rule-based engine
in `backend/analyzer.py` and `backend/risk_engine.py` already performs
full, explainable, input-dependent scoring.

To add a real ML-assisted score later:

1. Train a classifier on labelled phishing/scam text (e.g. TF-IDF +
   LogisticRegression via scikit-learn) and export it with `joblib`
   as `models/phishing_model.pkl`.
2. Load it in `backend/risk_engine.py` and blend its probability
   output into `calculate_risk()` as an additional signal, capped
   like the other contributions so it can't dominate the score.
3. Update `requirements.txt` if you add `joblib`.
