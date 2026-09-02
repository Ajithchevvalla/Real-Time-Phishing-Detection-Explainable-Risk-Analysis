"""Normalize a licensed Kaggle email CSV for PhishGuard.

Usage example:
  python data/prepare_kaggle_dataset.py path/to/input.csv data/phishing_dataset.csv

The input should contain subject/message/label, or common aliases such as
Subject/Body/Label. Only locally supplied files are processed.
"""
import sys
import pandas as pd

ALIASES = {
    "subject": ["subject", "Subject", "title", "Title"],
    "message": ["message", "Message", "body", "Body", "text", "Text", "content", "Content"],
    "label": ["label", "Label", "class", "Class", "target", "Target"]
}

def pick(df, names):
    for n in names:
        if n in df.columns:
            return n
    return None

if len(sys.argv) != 3:
    raise SystemExit("Usage: python data/prepare_kaggle_dataset.py INPUT.csv OUTPUT.csv")

src, dst = sys.argv[1], sys.argv[2]
df = pd.read_csv(src)
cols = {k: pick(df, v) for k, v in ALIASES.items()}
if not all(cols.values()):
    raise SystemExit(f"Could not find required columns. Found: {list(df.columns)}")
out = pd.DataFrame({
    "subject": df[cols["subject"]].fillna("").astype(str),
    "message": df[cols["message"]].fillna("").astype(str),
    "label": df[cols["label"]].astype(str).str.lower().map(lambda x: "phishing" if any(k in x for k in ["phish", "spam", "fraud", "malicious"]) else "legitimate")
})
out = out[out.message.str.strip().ne("")].drop_duplicates().reset_index(drop=True)
out.to_csv(dst, index=False)
print(f"Wrote {len(out):,} rows to {dst}")
