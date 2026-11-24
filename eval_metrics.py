import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score, accuracy_score

print("=====================================================")
print("1. UNSW-NB15 TEST SET EVALUATION (BINARY DETECTION)")
print("=====================================================")
test_df = pd.read_csv("data/UNSW_NB15_testing-set.csv")
y_true = test_df["label"].values

pkg_live = joblib.load("models/live_hybrid_intrusion_model.pkl")
rf = pkg_live["random_forest"]
enc = pkg_live["encoder"]
cols = pkg_live["feature_columns"]
cat_cols = pkg_live["categorical_columns"]

X_eval = test_df.copy()
for c in cols:
    if c not in X_eval.columns:
        X_eval[c] = 0
for c in cat_cols:
    if c in X_eval.columns:
        X_eval[c] = X_eval[c].fillna("-").astype(str)
X_eval[cat_cols] = enc.transform(X_eval[cat_cols])
X_mat = X_eval[cols].astype(np.float32)

probs = rf.predict_proba(X_mat)[:, 1]
y_pred = (probs >= 0.70).astype(int)

cm = confusion_matrix(y_true, y_pred)
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn)

print(f"Test Records: {len(test_df):,}")
print(f"Accuracy    : {accuracy_score(y_true, y_pred)*100:.2f}%")
print(f"Precision   : {precision_score(y_true, y_pred)*100:.2f}%")
print(f"Recall      : {recall_score(y_true, y_pred)*100:.2f}%")
print(f"F1 Score    : {f1_score(y_true, y_pred)*100:.2f}%")
print(f"False Positive Rate (FPR): {fpr*100:.2f}%")
print(f"Confusion Matrix:\n{cm}")
print(f"True Negatives (TN): {tn:,} | False Positives (FP): {fp:,}")
print(f"False Negatives (FN): {fn:,} | True Positives (TP): {tp:,}")

print("\n=====================================================")
print("2. UNSW-NB15 DNS SUBSET EVALUATION")
print("=====================================================")
dns_mask = (test_df["proto"] == "udp") & (test_df["service"] == "dns")
dns_y_true = y_true[dns_mask]
dns_y_pred = y_pred[dns_mask]
d_cm = confusion_matrix(dns_y_true, dns_y_pred)
d_tn, d_fp, d_fn, d_tp = d_cm.ravel()
d_fpr = d_fp / (d_fp + d_tn)
print(f"DNS Flows in Test Set: {dns_mask.sum():,}")
print(f"DNS Accuracy : {accuracy_score(dns_y_true, dns_y_pred)*100:.2f}%")
print(f"DNS Precision: {precision_score(dns_y_true, dns_y_pred)*100:.2f}%")
print(f"DNS Recall   : {recall_score(dns_y_true, dns_y_pred)*100:.2f}%")
print(f"DNS FPR on UNSW: {d_fpr*100:.2f}% (FP: {d_fp:,}, TN: {d_tn:,})")

print("\n=====================================================")
print("3. MULTICLASS ATTACK CLASSIFIER EVALUATION")
print("=====================================================")
pkg_multi = joblib.load("models/attack_classifier_model.pkl")
clf = pkg_multi["classifier"]
y_cat_true = test_df["attack_cat"].fillna("Normal").astype(str).str.strip().values
y_cat_pred = clf.predict(X_mat)
print(f"Multiclass Accuracy: {accuracy_score(y_cat_true, y_cat_pred)*100:.2f}%")
print(f"Weighted F1 Score  : {f1_score(y_cat_true, y_cat_pred, average='weighted')*100:.2f}%")
print(f"Macro F1 Score     : {f1_score(y_cat_true, y_cat_pred, average='macro')*100:.2f}%")

print("\n=====================================================")
print("4. REAL LIVE CAPTURED TRAFFIC EVALUATION (from dump)")
print("=====================================================")
live_df = pd.read_csv("reports/live_flows_dump.csv")
from modules.live_ai_engine import detect_live_flows
res_live = detect_live_flows(live_df)
print(f"Total Real Live Flows: {len(res_live):,}")
print(res_live["Final_Result"].value_counts())
print("\nRisk Level Breakdown:")
print(res_live["Risk_Level"].value_counts())
if "Attack_Category" in res_live.columns:
    print("\nAttack Category Breakdown:")
    print(res_live["Attack_Category"].value_counts())
