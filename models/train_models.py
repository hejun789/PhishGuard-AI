"""
Train and evaluate 4 ML models on the phishing URL dataset.
Saves the best model + scaler to models/ and writes charts to static/images/.
"""

import os
import sys
import pickle
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, classification_report
)

warnings.filterwarnings('ignore')

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_PATH    = os.path.join(PROJECT_ROOT, 'data', 'dataset.csv')
MODEL_DIR    = SCRIPT_DIR
IMAGES_DIR   = os.path.join(PROJECT_ROOT, 'static', 'images')

sys.path.append(PROJECT_ROOT)
from feature_extractor import get_feature_names

os.makedirs(IMAGES_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Plot style
# ---------------------------------------------------------------------------
PALETTE = {
    'bg'      : '#0d1117',
    'card'    : '#161b22',
    'green'   : '#00ff41',
    'cyan'    : '#00b4d8',
    'red'     : '#ff0043',
    'yellow'  : '#ffbe0b',
    'purple'  : '#bd93f9',
    'text'    : '#e6edf3',
    'grid'    : '#21262d',
}
MODEL_COLORS = [PALETTE['green'], PALETTE['cyan'], PALETTE['yellow'], PALETTE['purple']]

plt.rcParams.update({
    'figure.facecolor' : PALETTE['bg'],
    'axes.facecolor'   : PALETTE['card'],
    'axes.edgecolor'   : PALETTE['grid'],
    'axes.labelcolor'  : PALETTE['text'],
    'xtick.color'      : PALETTE['text'],
    'ytick.color'      : PALETTE['text'],
    'text.color'       : PALETTE['text'],
    'grid.color'       : PALETTE['grid'],
    'grid.linestyle'   : '--',
    'font.family'      : 'monospace',
    'font.size'        : 11,
})

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
print("=" * 60)
print("  PhishGuard AI — Model Training")
print("=" * 60)
print(f"\nLoading dataset: {DATA_PATH}")

df = pd.read_csv(DATA_PATH)
feature_names = get_feature_names()

X = df[feature_names].values
y = df['label'].values

print(f"Samples  : {len(df)}")
print(f"Features : {len(feature_names)}")
print(f"Legit    : {(y == 0).sum()}  |  Phishing: {(y == 1).sum()}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_sc = scaler.fit_transform(X_train)
X_test_sc  = scaler.transform(X_test)

# ---------------------------------------------------------------------------
# Train models
# ---------------------------------------------------------------------------
MODELS = {
    'Random Forest'      : (RandomForestClassifier(n_estimators=200, max_depth=20,
                                                    random_state=42, n_jobs=-1), False),
    'Gradient Boosting'  : (GradientBoostingClassifier(n_estimators=200, learning_rate=0.1,
                                                         max_depth=5, random_state=42), False),
    'Logistic Regression': (LogisticRegression(max_iter=2000, C=1.0,
                                                random_state=42), True),
    'SVM'                : (SVC(kernel='rbf', C=1.0, gamma='scale',
                                 probability=True, random_state=42), True),
}

results = {}
print()

for name, (model, needs_sc) in MODELS.items():
    Xtr = X_train_sc if needs_sc else X_train
    Xte = X_test_sc  if needs_sc else X_test

    print(f"Training {name}...", end=' ', flush=True)
    model.fit(Xtr, y_train)
    y_pred = model.predict(Xte)
    y_prob = model.predict_proba(Xte)[:, 1]

    results[name] = {
        'model'        : model,
        'needs_sc'     : needs_sc,
        'y_pred'       : y_pred,
        'y_prob'       : y_prob,
        'accuracy'     : accuracy_score(y_test, y_pred),
        'precision'    : precision_score(y_test, y_pred),
        'recall'       : recall_score(y_test, y_pred),
        'f1'           : f1_score(y_test, y_pred),
    }
    print(f"Acc={results[name]['accuracy']:.4f}  F1={results[name]['f1']:.4f}")

# ---------------------------------------------------------------------------
# Save best model
# ---------------------------------------------------------------------------
best_name = max(results, key=lambda n: results[n]['f1'])
best_info = results[best_name]

print(f"\nBest model: {best_name}  (F1={best_info['f1']:.4f})")

with open(os.path.join(MODEL_DIR, 'phishguard_model.pkl'), 'wb') as f:
    pickle.dump(best_info['model'], f)

with open(os.path.join(MODEL_DIR, 'scaler.pkl'), 'wb') as f:
    pickle.dump(scaler, f)

meta = {'name': best_name, 'needs_scaling': best_info['needs_sc']}
with open(os.path.join(MODEL_DIR, 'model_info.pkl'), 'wb') as f:
    pickle.dump(meta, f)

print("Model files saved to models/")

# ---------------------------------------------------------------------------
# Chart 1 — Model Comparison
# ---------------------------------------------------------------------------
print("\nGenerating visualizations...")

metrics     = ['accuracy', 'precision', 'recall', 'f1']
metric_lbls = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
model_names = list(results.keys())
x = np.arange(len(model_names))
width = 0.18

fig, ax = plt.subplots(figsize=(13, 6))
fig.patch.set_facecolor(PALETTE['bg'])

for i, (metric, lbl) in enumerate(zip(metrics, metric_lbls)):
    vals = [results[n][metric] for n in model_names]
    bars = ax.bar(x + i * width, vals, width, label=lbl,
                  color=MODEL_COLORS[i], alpha=0.85, edgecolor=PALETTE['bg'])
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.003,
                f'{v:.3f}', ha='center', va='bottom', fontsize=8,
                color=PALETTE['text'])

ax.set_xticks(x + width * 1.5)
ax.set_xticklabels(model_names, fontsize=10)
ax.set_ylim(0.7, 1.05)
ax.set_ylabel('Score')
ax.set_title('Model Performance Comparison', fontsize=14, color=PALETTE['green'],
              pad=15, fontweight='bold')
ax.legend(loc='lower right', framealpha=0.3)
ax.grid(True, axis='y', alpha=0.4)
ax.spines[['top', 'right']].set_visible(False)
plt.tight_layout()
plt.savefig(os.path.join(IMAGES_DIR, 'model_comparison.png'), dpi=150, bbox_inches='tight')
plt.close()

# ---------------------------------------------------------------------------
# Chart 2 — Confusion Matrix (best model)
# ---------------------------------------------------------------------------
cm = confusion_matrix(y_test, best_info['y_pred'])
fig, ax = plt.subplots(figsize=(6, 5))
fig.patch.set_facecolor(PALETTE['bg'])

sns.heatmap(
    cm, annot=True, fmt='d', cmap='Blues',
    xticklabels=['Legitimate', 'Phishing'],
    yticklabels=['Legitimate', 'Phishing'],
    linewidths=0.5, linecolor=PALETTE['bg'],
    cbar_kws={'shrink': 0.8}, ax=ax
)
ax.set_xlabel('Predicted Label', labelpad=10)
ax.set_ylabel('True Label', labelpad=10)
ax.set_title(f'Confusion Matrix — {best_name}', fontsize=13,
             color=PALETTE['cyan'], pad=12, fontweight='bold')
plt.tight_layout()
plt.savefig(os.path.join(IMAGES_DIR, 'confusion_matrix.png'), dpi=150, bbox_inches='tight')
plt.close()

# ---------------------------------------------------------------------------
# Chart 3 — ROC Curves (all models)
# ---------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(8, 6))
fig.patch.set_facecolor(PALETTE['bg'])

ax.plot([0, 1], [0, 1], '--', color=PALETTE['grid'], lw=1.5, label='Random (AUC = 0.50)')

for (name, info), color in zip(results.items(), MODEL_COLORS):
    fpr, tpr, _ = roc_curve(y_test, info['y_prob'])
    roc_auc = auc(fpr, tpr)
    ax.plot(fpr, tpr, color=color, lw=2,
            label=f'{name} (AUC = {roc_auc:.4f})')

ax.set_xlim([0.0, 1.0])
ax.set_ylim([0.0, 1.05])
ax.set_xlabel('False Positive Rate')
ax.set_ylabel('True Positive Rate')
ax.set_title('ROC Curves — All Models', fontsize=13,
             color=PALETTE['yellow'], pad=12, fontweight='bold')
ax.legend(loc='lower right', fontsize=9, framealpha=0.3)
ax.grid(True, alpha=0.3)
ax.spines[['top', 'right']].set_visible(False)
plt.tight_layout()
plt.savefig(os.path.join(IMAGES_DIR, 'roc_curves.png'), dpi=150, bbox_inches='tight')
plt.close()

# ---------------------------------------------------------------------------
# Chart 4 — Feature Importance (Random Forest)
# ---------------------------------------------------------------------------
rf_model = results['Random Forest']['model']
importances = rf_model.feature_importances_
indices = np.argsort(importances)[::-1]
feat_names_sorted = [feature_names[i] for i in indices]
imp_sorted = importances[indices]

fig, ax = plt.subplots(figsize=(10, 7))
fig.patch.set_facecolor(PALETTE['bg'])

colors = [PALETTE['green'] if i < 5 else PALETTE['cyan'] if i < 12 else PALETTE['purple']
          for i in range(len(feat_names_sorted))]
bars = ax.barh(feat_names_sorted[::-1], imp_sorted[::-1], color=colors[::-1],
               edgecolor=PALETTE['bg'], height=0.7)

for bar, v in zip(bars, imp_sorted[::-1]):
    ax.text(bar.get_width() + 0.001, bar.get_y() + bar.get_height() / 2,
            f'{v:.4f}', va='center', fontsize=8, color=PALETTE['text'])

ax.set_xlabel('Feature Importance (Gini)')
ax.set_title('Feature Importance — Random Forest', fontsize=13,
             color=PALETTE['green'], pad=12, fontweight='bold')
ax.grid(True, axis='x', alpha=0.3)
ax.spines[['top', 'right']].set_visible(False)
plt.tight_layout()
plt.savefig(os.path.join(IMAGES_DIR, 'feature_importance.png'), dpi=150, bbox_inches='tight')
plt.close()

print("Charts saved to static/images/")
print("\n" + "=" * 60)
print("  Training complete!")
print(f"  Best model : {best_name}")
print(f"  Accuracy   : {best_info['accuracy']:.4f}")
print(f"  Precision  : {best_info['precision']:.4f}")
print(f"  Recall     : {best_info['recall']:.4f}")
print(f"  F1-Score   : {best_info['f1']:.4f}")
print("=" * 60)
