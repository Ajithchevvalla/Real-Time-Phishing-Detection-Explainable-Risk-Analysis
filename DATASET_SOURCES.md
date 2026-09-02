# Dataset sources

A Kaggle public notebook describes a combined phishing/spam email corpus of approximately 82,500 emails, including 42,891 spam and 39,595 legitimate emails, assembled from CEAS_08, Enron, Ling, Nazario, Nigerian_Fraud, SpamAssassin and phishing-email datasets.

Reference: https://www.kaggle.com/code/zafko8/phishing-email-and-spam-sms-ai-detection-tool/input

The shipped `data/phishing_dataset.csv` is a self-contained expanded demonstration dataset. It is not claimed to be a byte-for-byte copy of that Kaggle corpus. This avoids requiring a Kaggle account/API credentials and keeps the project runnable offline.

For a production-quality evaluation, replace the CSV with a properly licensed email corpus containing:

- `subject`
- `message`
- `label` (`phishing` or `legitimate`)

The model retrains automatically from the CSV on first prediction.
