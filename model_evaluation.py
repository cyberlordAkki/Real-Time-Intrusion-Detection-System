import os, warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

warnings.filterwarnings("ignore")

from sklearn.model_selection    import train_test_split
from sklearn.preprocessing      import LabelEncoder, MinMaxScaler
from sklearn.metrics            import (accuracy_score, precision_score,
                                        recall_score, f1_score,
                                        confusion_matrix, roc_curve, auc)
from sklearn.tree               import DecisionTreeClassifier
from sklearn.ensemble           import RandomForestClassifier, AdaBoostClassifier
from xgboost                    import XGBClassifier
from lightgbm                   import LGBMClassifier
from catboost                   import CatBoostClassifier
import joblib

# ──────────────────────────────────────────────
# PATHS
# ──────────────────────────────────────────────
DIR         = os.path.dirname(os.path.abspath(__file__))
KDD_TRAIN   = os.path.join(DIR, "kdd_train.csv")
KDD_TEST    = os.path.join(DIR, "kdd_test.csv")
RESULTS_DIR = os.path.join(DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# ──────────────────────────────────────────────
# COLUMN NAMES  (NSL-KDD standard)
# ──────────────────────────────────────────────
COLS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
    "srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label","difficulty"
]

# ──────────────────────────────────────────────
# BINARY ATTACK MAP  (DoS vs Normal only)
# Probe / R2L / U2R rows are dropped
# ──────────────────────────────────────────────
ATTACK_MAP = {
    "normal":        "Normal",
    # DoS family
    "neptune":       "DoS", "back":          "DoS", "land":          "DoS",
    "pod":           "DoS", "smurf":         "DoS", "teardrop":      "DoS",
    "mailbomb":      "DoS", "apache2":       "DoS", "processtable":  "DoS",
    "udpstorm":      "DoS",
}

# ──────────────────────────────────────────────
# COLOUR PALETTE  (dark-theme friendly)
# ──────────────────────────────────────────────
C_DOS    = "#ef4444"   # red
C_NORMAL = "#22c55e"   # green
C_ACCENT = "#3b82f6"   # blue
C_BG     = "#0b0f1a"
C_PANEL  = "#111827"
C_GRID   = "#1e2d45"
C_TEXT   = "#e2e8f4"
C_SUB    = "#5a7192"

MODEL_COLORS = [
    "#3b82f6","#f59e0b","#10b981","#8b5cf6","#ef4444","#06b6d4"
]

plt.rcParams.update({
    "figure.facecolor":  C_BG,
    "axes.facecolor":    C_PANEL,
    "axes.edgecolor":    C_GRID,
    "axes.labelcolor":   C_TEXT,
    "xtick.color":       C_TEXT,
    "ytick.color":       C_TEXT,
    "text.color":        C_TEXT,
    "grid.color":        C_GRID,
    "legend.facecolor":  C_PANEL,
    "legend.edgecolor":  C_GRID,
})


# ══════════════════════════════════════════════
# [1]  LOAD & PREPROCESS
# ══════════════════════════════════════════════
print("=" * 60)
print("  RTIDS — Binary Model Evaluation (DoS vs Normal)")
print("=" * 60)

def load_and_preprocess(path):
    df = pd.read_csv(path, header=None, names=COLS)
    df = df[df["label"] != "label"]                              # drop stray header rows
    df.drop(columns=["difficulty"], inplace=True, errors="ignore")
    df["label"] = df["label"].str.strip().str.replace(r"\.$", "", regex=True)
    df["label"] = df["label"].map(ATTACK_MAP)
    df.dropna(subset=["label"], inplace=True)                    # drops Probe/R2L/U2R

    X = df.drop("label", axis=1).copy()
    y = df["label"].values

    # Encode categorical features
    for col in ["protocol_type", "service", "flag"]:
        enc = LabelEncoder()
        X[col] = enc.fit_transform(X[col].astype(str))

    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)
    return X, y


print("\n[1] Loading data...")
X_train_raw, y_train = load_and_preprocess(KDD_TRAIN)
X_test_raw,  y_test  = load_and_preprocess(KDD_TEST)

# Scale
scaler  = MinMaxScaler()
X_train = scaler.fit_transform(X_train_raw)
X_test  = scaler.transform(X_test_raw)

# Encode labels  ->  DoS=0, Normal=1  (alphabetical)
le = LabelEncoder()
y_train_enc = le.fit_transform(y_train)
y_test_enc  = le.transform(y_test)
CLASS_NAMES = list(le.classes_)   # ["DoS", "Normal"]

print(f"  Train : {X_train.shape[0]:,} rows  |  "
      f"DoS={int((y_train=='DoS').sum()):,}  Normal={int((y_train=='Normal').sum()):,}")
print(f"  Test  : {X_test.shape[0]:,} rows  |  "
      f"DoS={int((y_test=='DoS').sum()):,}  Normal={int((y_test=='Normal').sum()):,}")


# ══════════════════════════════════════════════
# [2]  PREPROCESSING PIPELINE SUMMARY
# ══════════════════════════════════════════════
print("\n" + "=" * 60)
print("  [2] PREPROCESSING PIPELINE SUMMARY")
print("=" * 60)
print(f"  Step 1 : Load CSV  ->  {len(COLS)-2} features + 1 label  ('difficulty' dropped)")
print(f"  Step 2 : Label map ->  DoS / Normal only")
print(f"           Probe / R2L / U2R rows DROPPED")
print(f"  Step 3 : Categorical encode  (LabelEncoder)")
print(f"           Cols: protocol_type, service, flag")
print(f"  Step 4 : All columns -> numeric  +  fillna(0)")
print(f"  Step 5 : MinMaxScaler  [0, 1]")
print(f"           fit on TRAIN only, transform TEST  (no data leakage)")
print(f"  Step 6 : Target encode  ->  DoS=0, Normal=1")
print(f"\n  Total features used      : {X_train_raw.shape[1]}")
print(f"  Categorical (encoded)    : protocol_type, service, flag")
print(f"  Binary flag cols         : land, logged_in, root_shell,")
print(f"                             su_attempted, is_host_login, is_guest_login")
print(f"  Continuous numeric cols  : {X_train_raw.shape[1] - 3 - 6} features")


# ══════════════════════════════════════════════
# [3]  TRAINING SPLIT & VALIDATION INFO
# ══════════════════════════════════════════════
print("\n" + "=" * 60)
print("  [3] TRAINING SPLIT & VALIDATION STRATEGY")
print("=" * 60)
n_train   = X_train.shape[0]
n_test    = X_test.shape[0]
total     = n_train + n_test
train_pct = n_train / total * 100
test_pct  = n_test  / total * 100

print(f"  Split Type      : Predefined official NSL-KDD split")
print(f"  Train file      : kdd_train.csv   ->  {n_train:,} samples  ({train_pct:.1f}%)")
print(f"  Test  file      : kdd_test.csv    ->  {n_test:,} samples  ({test_pct:.1f}%)")
print(f"  Total samples   : {total:,}")
print(f"  Approx ratio    : {train_pct:.0f} / {test_pct:.0f}  (Train / Test)")
print(f"\n  Cross-Validation: NOT used")
print(f"  Reason          : NSL-KDD provides a standard benchmark split.")
print(f"                    Using the official split ensures fair comparison")
print(f"                    with published literature. No random shuffle needed.")
print(f"  Random state    : 42  (all models, for reproducibility)")


# ══════════════════════════════════════════════
# [4]  DATASET STATISTICS  (CMD + PNG)
# ══════════════════════════════════════════════
print("\n" + "=" * 60)
print("  [4] DATASET STATISTICS  (Train set — raw values before scaling)")
print("=" * 60)

stats_df = X_train_raw.describe().T
stats_df["variance"] = X_train_raw.var()
stats_df = stats_df[["mean", "std", "variance", "min", "max"]]
stats_df.columns = ["Mean", "Std Dev", "Variance", "Min", "Max"]

# Print top 15 features sorted by variance
top_var = stats_df.sort_values("Variance", ascending=False).head(15)
print(f"\n  Top 15 features by Variance (most informative):\n")
print(f"  {'Feature':<36} {'Mean':>12} {'Std Dev':>12} {'Variance':>14}")
print(f"  {'-'*36} {'-'*12} {'-'*12} {'-'*14}")
for feat, row in top_var.iterrows():
    print(f"  {feat:<36} {row['Mean']:>12.4f} {row['Std Dev']:>12.4f} {row['Variance']:>14.4f}")

# Save full stats CSV
stats_csv = os.path.join(RESULTS_DIR, "feature_statistics.csv")
stats_df.to_csv(stats_csv)
print(f"\n  [✓] Full stats (all 41 features) saved -> results/feature_statistics.csv")

# ── Plot: Mean +/- Std Dev bar chart ───────────────────────
print("\n[4a] Generating feature statistics plot...")
top15_feats = top_var.index.tolist()
means = top_var["Mean"].values
stds  = top_var["Std Dev"].values

fig, ax = plt.subplots(figsize=(10, 6))
y_pos = np.arange(len(top15_feats))
ax.barh(y_pos, means, xerr=stds, color=C_ACCENT, ecolor=C_TEXT,
        capsize=4, edgecolor=C_GRID, linewidth=0.6, height=0.6, alpha=0.85)
ax.set_yticks(y_pos)
ax.set_yticklabels(top15_feats, fontsize=9)
ax.set_xlabel("Mean Value (raw, before scaling)")
ax.set_title("Top 15 Features — Mean +/- Std Dev (NSL-KDD Train)",
             fontsize=12, fontweight="bold", pad=12)
ax.xaxis.grid(True, linestyle="--", alpha=0.4)
ax.set_axisbelow(True)
fig.tight_layout()
fig.savefig(os.path.join(RESULTS_DIR, "feature_statistics.png"), dpi=150)
plt.close(fig)
print("  [✓] Saved: feature_statistics.png")


# ══════════════════════════════════════════════
# [5]  CORRELATION HEATMAP  (CMD + PNG)
# ══════════════════════════════════════════════
print("\n" + "=" * 60)
print("  [5] CORRELATION HEATMAP  (Top 15 features by variance)")
print("=" * 60)

top15_df    = X_train_raw[top15_feats]
corr_matrix = top15_df.corr()

# CMD: print strongly correlated pairs
print("\n  Strongly correlated feature pairs  (|r| > 0.70):\n")
print(f"  {'Feature A':<32} {'Feature B':<32} {'Corr':>8}")
print(f"  {'-'*32} {'-'*32} {'-'*8}")
printed   = set()
found_any = False
for i in range(len(corr_matrix.columns)):
    for j in range(i + 1, len(corr_matrix.columns)):
        r  = corr_matrix.iloc[i, j]
        if abs(r) > 0.70:
            fa  = corr_matrix.columns[i]
            fb  = corr_matrix.columns[j]
            key = tuple(sorted([fa, fb]))
            if key not in printed:
                printed.add(key)
                print(f"  {fa:<32} {fb:<32} {r:>8.4f}")
                found_any = True
if not found_any:
    print("  (No pairs with |r| > 0.70 found in top-15 features)")

# ── Plot: Heatmap ────────────────────────────────────────────
print("\n[5a] Generating correlation heatmap...")
fig, ax = plt.subplots(figsize=(12, 10))
cmap    = sns.diverging_palette(220, 10, as_cmap=True)
sns.heatmap(
    corr_matrix,
    ax=ax,
    cmap=cmap,
    annot=True,
    fmt=".2f",
    linewidths=0.4,
    linecolor=C_GRID,
    annot_kws={"size": 7},
    vmin=-1, vmax=1,
    square=True,
    cbar_kws={"shrink": 0.75, "label": "Pearson r"}
)
ax.set_title("Correlation Heatmap — Top 15 Features (NSL-KDD Train)",
             fontsize=12, fontweight="bold", pad=14)
ax.tick_params(axis="x", labelsize=8, rotation=45)
ax.tick_params(axis="y", labelsize=8, rotation=0)
fig.tight_layout()
fig.savefig(os.path.join(RESULTS_DIR, "correlation_heatmap.png"), dpi=150)
plt.close(fig)
print("  [✓] Saved: correlation_heatmap.png")


# ══════════════════════════════════════════════
# [6]  DEFINE MODELS
# ══════════════════════════════════════════════
models = {
    "XGBoost": XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        use_label_encoder=False, eval_metric="logloss",
        random_state=42, n_jobs=-1
    ),
    "AdaBoost": AdaBoostClassifier(
        n_estimators=200, learning_rate=0.5, random_state=42
    ),
    "Decision Tree": DecisionTreeClassifier(
        max_depth=20, min_samples_split=5, random_state=42
    ),
    "CatBoost": CatBoostClassifier(
        iterations=200, depth=6, learning_rate=0.1,
        verbose=0, random_state=42
    ),
    "LightGBM": LGBMClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        verbose=-1, random_state=42, n_jobs=-1
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=200, max_depth=20, random_state=42, n_jobs=-1
    ),
}


# ══════════════════════════════════════════════
# [7]  TRAIN & EVALUATE
# ══════════════════════════════════════════════
print("\n" + "=" * 60)
print("  [6] TRAINING MODELS")
print("=" * 60)

results        = {}
trained_models = {}

for name, model in models.items():
    print(f"  Training {name}...")
    model.fit(X_train, y_train_enc)
    y_pred = model.predict(X_test)

    acc  = accuracy_score (y_test_enc, y_pred) * 100
    prec = precision_score(y_test_enc, y_pred, average="weighted", zero_division=0) * 100
    rec  = recall_score   (y_test_enc, y_pred, average="weighted", zero_division=0) * 100
    f1   = f1_score       (y_test_enc, y_pred, average="weighted", zero_division=0) * 100

    results[name] = {
        "Accuracy (%)":  round(acc,  6),
        "Precision (%)": round(prec, 6),
        "Recall (%)":    round(rec,  6),
        "F1 Score (%)":  round(f1,   6),
    }
    trained_models[name] = model
    print(f"    Accuracy:{acc:.2f}%  Precision:{prec:.2f}%  "
          f"Recall:{rec:.2f}%  F1:{f1:.2f}%")

# Sort by Accuracy descending
results_df    = pd.DataFrame(results).T.sort_values("Accuracy (%)", ascending=False)
best_name     = results_df.index[0]
baseline_name = results_df.index[1]

print(f"\n  Final Results:")
print(results_df.to_string())
print(f"\n  BEST MODEL    : {best_name}")
print(f"  BASELINE MODEL: {baseline_name}")

# Save CSV
results_df.to_csv(os.path.join(RESULTS_DIR, "final_results.csv"))

# Save best + baseline models
joblib.dump(trained_models[best_name],     os.path.join(RESULTS_DIR, "best_model.pkl"))
joblib.dump(trained_models[baseline_name], os.path.join(RESULTS_DIR, "baseline_model.pkl"))
print(f"\n  [✓] Models saved -> results/best_model.pkl  &  baseline_model.pkl")


# ══════════════════════════════════════════════
# [8]  PLOTS
# ══════════════════════════════════════════════
print("\n" + "=" * 60)
print("  [7] GENERATING PLOTS")
print("=" * 60)

# ── 8a. Class Distribution ──────────────────────────────────
fig, ax = plt.subplots(figsize=(6, 4))
labels_plot = ["DoS", "Normal"]
counts = [(y_train == c).sum() for c in labels_plot]
bars = ax.bar(labels_plot, counts, color=[C_DOS, C_NORMAL], width=0.4,
              edgecolor=C_GRID, linewidth=0.8)
for bar, cnt in zip(bars, counts):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(counts)*0.01,
            f"{cnt:,}", ha="center", va="bottom", fontsize=10, color=C_TEXT)
ax.set_title("Class Distribution (Train)", fontsize=13, fontweight="bold", pad=12)
ax.set_ylabel("Sample Count")
ax.yaxis.grid(True, linestyle="--", alpha=0.4)
ax.set_axisbelow(True)
fig.tight_layout()
fig.savefig(os.path.join(RESULTS_DIR, "class_distribution.png"), dpi=150)
plt.close(fig)
print("  [✓] Saved: class_distribution.png")

# ── 8b. Model Comparison Bar Chart ─────────────────────────
fig, ax = plt.subplots(figsize=(10, 5))
model_names = list(results_df.index)
accs   = results_df["Accuracy (%)"].values
colors = [MODEL_COLORS[i % len(MODEL_COLORS)] for i in range(len(model_names))]
bars   = ax.barh(model_names[::-1], accs[::-1], color=colors[::-1],
                 edgecolor=C_GRID, linewidth=0.6, height=0.55)
for bar, val in zip(bars, accs[::-1]):
    ax.text(bar.get_width() - 0.15, bar.get_y() + bar.get_height()/2,
            f"{val:.2f}%", va="center", ha="right", fontsize=9,
            color=C_BG, fontweight="bold")
ax.set_xlim(min(accs) - 1, 100.5)
ax.set_xlabel("Accuracy (%)")
ax.set_title("Model Accuracy Comparison — RTIDS (DoS vs Normal)",
             fontsize=12, fontweight="bold", pad=12)
ax.xaxis.grid(True, linestyle="--", alpha=0.4)
ax.set_axisbelow(True)
fig.tight_layout()
fig.savefig(os.path.join(RESULTS_DIR, "model_comparison.png"), dpi=150)
plt.close(fig)
print("  [✓] Saved: model_comparison.png")

# ── 8c. Confusion Matrix (best model) ──────────────────────
best_model  = trained_models[best_name]
y_pred_best = best_model.predict(X_test)
cm = confusion_matrix(y_test_enc, y_pred_best)

fig, ax = plt.subplots(figsize=(5, 4))
im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
plt.colorbar(im, ax=ax)
ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
ax.set_xticklabels(CLASS_NAMES); ax.set_yticklabels(CLASS_NAMES)
ax.set_xlabel("Predicted Label"); ax.set_ylabel("True Label")
ax.set_title(f"Confusion Matrix — {best_name}", fontsize=11, fontweight="bold", pad=10)
thresh = cm.max() / 2
for i in range(2):
    for j in range(2):
        ax.text(j, i, f"{cm[i,j]:,}", ha="center", va="center", fontsize=13,
                color="white" if cm[i,j] > thresh else C_TEXT)
fig.tight_layout()
fig.savefig(os.path.join(RESULTS_DIR, "confusion_matrix.png"), dpi=150)
plt.close(fig)
print("  [✓] Saved: confusion_matrix.png")

# ── 8d. ROC Curve (Binary) ─────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 5))
for (name, model), color in zip(trained_models.items(), MODEL_COLORS):
    try:
        if hasattr(model, "predict_proba"):
            y_score = model.predict_proba(X_test)[:, 0]
        elif hasattr(model, "decision_function"):
            y_score = model.decision_function(X_test)
        else:
            continue
        fpr, tpr, _ = roc_curve((y_test_enc == 0).astype(int), y_score)
        roc_auc = auc(fpr, tpr)
        lw = 2.5 if name == best_name else 1.2
        ax.plot(fpr, tpr, color=color, lw=lw,
                label=f"{name} (AUC = {roc_auc:.4f})")
    except Exception as e:
        print(f"  [WARN] ROC skipped for {name}: {e}")
ax.plot([0, 1], [0, 1], "k--", lw=0.8, alpha=0.5)
ax.set_xlim([-0.01, 1.01]); ax.set_ylim([-0.01, 1.02])
ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
ax.set_title("ROC Curve — RTIDS (DoS vs Normal)",
             fontsize=12, fontweight="bold", pad=12)
ax.legend(loc="lower right", fontsize=8)
ax.xaxis.grid(True, linestyle="--", alpha=0.4)
ax.yaxis.grid(True, linestyle="--", alpha=0.4)
fig.tight_layout()
fig.savefig(os.path.join(RESULTS_DIR, "roc_curve.png"), dpi=150)
plt.close(fig)
print("  [✓] Saved: roc_curve.png")

# ── 8e. Feature Importance (XGBoost) — CMD + PNG ───────────
try:
    xgb_model   = trained_models["XGBoost"]
    importances = xgb_model.feature_importances_
    feat_names  = list(X_train_raw.columns)
    top_n       = 15
    sorted_idx  = np.argsort(importances)[-top_n:]

    # CMD print
    print(f"\n  Top {top_n} Feature Importances (XGBoost):\n")
    print(f"  {'Rank':<6} {'Feature':<36} {'Importance':>12}")
    print(f"  {'-'*6} {'-'*36} {'-'*12}")
    for rank, idx in enumerate(sorted_idx[::-1], 1):
        print(f"  {rank:<6} {feat_names[idx]:<36} {importances[idx]:>12.6f}")

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(
        [feat_names[i] for i in sorted_idx],
        importances[sorted_idx],
        color=C_ACCENT, edgecolor=C_GRID, linewidth=0.6
    )
    ax.set_xlabel("Importance Score")
    ax.set_title(f"Top {top_n} Feature Importances — XGBoost",
                 fontsize=11, fontweight="bold", pad=10)
    ax.xaxis.grid(True, linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS_DIR, "feature_importance.png"), dpi=150)
    plt.close(fig)
    print("  [✓] Saved: feature_importance.png")
except Exception as e:
    print(f"  [WARN] Feature importance skipped: {e}")


# ══════════════════════════════════════════════
# DONE — FULL SUMMARY
# ══════════════════════════════════════════════
print("\n" + "=" * 60)
print("  ALL OUTPUTS GENERATED SUCCESSFULLY")
print("=" * 60)
print(f"  BEST MODEL    : {best_name}  "
      f"({results_df.loc[best_name,'Accuracy (%)']:.2f}%)")
print(f"  BASELINE MODEL: {baseline_name}  "
      f"({results_df.loc[baseline_name,'Accuracy (%)']:.2f}%)")
print(f"\n  Files saved in  ->  {RESULTS_DIR}/")
print(f"    class_distribution.png")
print(f"    model_comparison.png")
print(f"    confusion_matrix.png")
print(f"    roc_curve.png")
print(f"    feature_importance.png")
print(f"    feature_statistics.png      [NEW]")
print(f"    correlation_heatmap.png     [NEW]")
print(f"    feature_statistics.csv      [NEW]")
print(f"    final_results.csv")
print(f"    best_model.pkl")
print(f"    baseline_model.pkl")
print("=" * 60)
