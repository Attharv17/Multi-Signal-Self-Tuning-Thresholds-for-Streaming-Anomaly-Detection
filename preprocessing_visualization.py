# -*- coding: utf-8 -*-
"""
Data Preprocessing Analysis & Visualization
============================================
Project : Multi-Signal Self-Tuning Thresholds for Streaming Anomaly Detection
Dataset : CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity)
Author  : Pravar Khandelwal
Purpose : Generate publication-quality preprocessing graphs for university PPT

Generates the 6 essential preprocessing graphs:
  - 02_missing_values.png
  - 04_outlier_boxplots.png
  - 05_correlation_heatmap.png
  - 06_before_after_preprocessing.png
  - 09_rolling_statistics.png
  - 10_final_preprocessed_data.png

Reads ACTUAL raw + preprocessed project files. Does NOT modify anomaly-detection logic.
Output directory: outputs/preprocessing_graphs/
"""

import sys
import io
import warnings
import json
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker
import matplotlib.patches as mpatches
import seaborn as sns

warnings.filterwarnings("ignore")

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent
RAW_DIR      = PROJECT_ROOT / "Raw Dataset"
FINAL_DIR    = PROJECT_ROOT / "processed" / "final_features"
OUT_DIR      = PROJECT_ROOT / "outputs" / "preprocessing_graphs"
OUT_DIR.mkdir(parents=True, exist_ok=True)

print(f"Output directory: {OUT_DIR}")

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL STYLE — academic / professional
# ─────────────────────────────────────────────────────────────────────────────
TITLE_SIZE   = 16
LABEL_SIZE   = 13
TICK_SIZE    = 11
LEGEND_SIZE  = 11
DPI          = 300
FIG_FACE     = "#f9f9f9"
BENIGN_COLOR = "#2E86AB"
ATTACK_COLOR = "#E84855"
LOG1P_COLOR  = "#3BB273"

plt.rcParams.update({
    "font.family"          : "DejaVu Sans",
    "axes.titlesize"       : TITLE_SIZE,
    "axes.labelsize"       : LABEL_SIZE,
    "xtick.labelsize"      : TICK_SIZE,
    "ytick.labelsize"      : TICK_SIZE,
    "legend.fontsize"      : LEGEND_SIZE,
    "axes.spines.top"      : False,
    "axes.spines.right"    : False,
    "figure.facecolor"     : FIG_FACE,
    "axes.facecolor"       : FIG_FACE,
    "savefig.facecolor"    : FIG_FACE,
    "grid.alpha"           : 0.35,
    "grid.linestyle"       : "--",
})

# ─────────────────────────────────────────────────────────────────────────────
# DATA LOADING
# ─────────────────────────────────────────────────────────────────────────────
SAMPLE_N = 20_000

print("\n[Data] Loading raw sample (Wednesday — largest, richest attack mix)...")
RAW_FILE = RAW_DIR / "Wednesday-workingHours.pcap_ISCX.csv"
raw_df   = pd.read_csv(RAW_FILE, low_memory=False, encoding="utf-8",
                        encoding_errors="replace")
raw_df.columns = raw_df.columns.str.strip()
for c in ["Flow Bytes/s", "Flow Packets/s"]:
    raw_df[c] = raw_df[c].replace([np.inf, -np.inf], np.nan)
print(f"  Raw rows: {len(raw_df):,}  Cols: {raw_df.shape[1]}")

print("[Data] Loading preprocessed parquet (Wednesday)...")
PROC_PARQUET = FINAL_DIR / "Wednesday-workingHours.parquet"
proc_df      = pd.read_parquet(PROC_PARQUET)
print(f"  Processed rows: {len(proc_df):,}  Cols: {proc_df.shape[1]}")

raw_sample  = raw_df.sample(n=min(SAMPLE_N, len(raw_df)),   random_state=42).reset_index(drop=True)
proc_sample = proc_df.sample(n=min(SAMPLE_N, len(proc_df)), random_state=42).reset_index(drop=True)

print("[Data] Loading inspection JSON...")
JSON_PATH = PROJECT_ROOT / "json_results" / "inspection_results.json"
with open(JSON_PATH, "r", encoding="utf-8") as f:
    inspection = json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────────────────────────────────────
def save_fig(fig, filename, title_for_print):
    path = OUT_DIR / filename
    fig.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {filename}  ({title_for_print})")


# ═════════════════════════════════════════════════════════════════════════════
# 02 — MISSING VALUES ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════
print("\n[02] Missing Values Analysis...")

files_data  = inspection["files"]
all_cols_79 = files_data[0]["column_names"]

missing_agg = {}
inf_agg     = {}
for col in all_cols_79:
    missing_agg[col] = sum(r["missing_per_column"].get(col, 0) for r in files_data)
    inf_agg[col]     = sum(r.get("pos_inf_per_column", {}).get(col, 0) for r in files_data)

display_cols   = list(set([k for k,v in missing_agg.items() if v > 0] +
                           [k for k,v in inf_agg.items()    if v > 0]))
other_cols_cnt = len(all_cols_79) - len(display_cols)

nan_vals = [missing_agg.get(c, 0) for c in display_cols]
inf_vals = [inf_agg.get(c, 0)     for c in display_cols]

fig02, axes02 = plt.subplots(1, 2, figsize=(14, 6))
fig02.suptitle("Missing Values Before Preprocessing\n(Across All 8 Raw Files — 2,830,743 Rows Total)",
               fontsize=15, fontweight="bold")

ax02L = axes02[0]
short_labels = [c.replace("/", "/\n") for c in display_cols]
bars = ax02L.bar(short_labels, nan_vals, color=ATTACK_COLOR, edgecolor="white", width=0.55)
ax02L.set_title("NaN Count per Feature (Raw Dataset)", fontweight="bold")
ax02L.set_xlabel("Feature")
ax02L.set_ylabel("Number of NaN Values")
ax02L.set_xticks(range(len(short_labels)))
ax02L.set_xticklabels(short_labels, fontsize=11)
ax02L.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, _: f"{int(x):,}"))
for bar, val in zip(bars, nan_vals):
    if val > 0:
        ax02L.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 20,
                   f"{val:,}", ha="center", va="bottom", fontsize=11,
                   fontweight="bold", color=ATTACK_COLOR)
ax02L.set_ylim(0, max(nan_vals)*1.25 if max(nan_vals) > 0 else 5)
ax02L.annotate(f"All other {other_cols_cnt} features: 0 NaN",
               xy=(0.5, 0.92), xycoords="axes fraction", ha="center", fontsize=10,
               bbox=dict(boxstyle="round,pad=0.3", facecolor="#d4edda", alpha=0.8))
ax02L.grid(axis="y")

ax02R = axes02[1]
bars2 = ax02R.bar(short_labels, inf_vals, color="#F4845F", edgecolor="white", width=0.55)
ax02R.set_title("+Infinity Count per Feature (Raw Dataset)", fontweight="bold")
ax02R.set_xlabel("Feature")
ax02R.set_ylabel("Number of +Inf Values")
ax02R.set_xticks(range(len(short_labels)))
ax02R.set_xticklabels(short_labels, fontsize=11)
ax02R.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, _: f"{int(x):,}"))
for bar, val in zip(bars2, inf_vals):
    if val > 0:
        ax02R.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 30,
                   f"{val:,}", ha="center", va="bottom", fontsize=11,
                   fontweight="bold", color="#E65100")
ax02R.set_ylim(0, max(inf_vals)*1.25 if max(inf_vals) > 0 else 5)
ax02R.annotate("Root cause: Flow Duration = 0 (division by zero)",
               xy=(0.5, 0.92), xycoords="axes fraction", ha="center", fontsize=10,
               bbox=dict(boxstyle="round,pad=0.3", facecolor="#fff3cd", alpha=0.8))
ax02R.grid(axis="y")

fig02.tight_layout()
save_fig(fig02, "02_missing_values.png", "Missing Values Analysis")


# ═════════════════════════════════════════════════════════════════════════════
# 04 — OUTLIER BOX PLOTS BEFORE PREPROCESSING
# ═════════════════════════════════════════════════════════════════════════════
print("[04] Outlier Box Plots Before Preprocessing...")

outlier_features = [
    "Flow Bytes/s", "Flow Packets/s", "Flow Duration",
    "Total Fwd Packets", "Fwd Packet Length Max", "Flow IAT Max",
]

fig04, axes04 = plt.subplots(2, 3, figsize=(17, 10))
fig04.suptitle("Outlier Analysis Before Preprocessing\n"
               "(Box Plots — Raw Values on log scale, Wednesday Sample)",
               fontsize=15, fontweight="bold", y=1.01)

for ax, col in zip(axes04.flat, outlier_features):
    data     = raw_sample[col].dropna()
    log_data = np.log1p(data.clip(lower=0))
    ax.boxplot(log_data, vert=True, patch_artist=True,
               flierprops=dict(marker=".", markersize=2.5,
                               color=ATTACK_COLOR, alpha=0.4),
               medianprops=dict(color="#1A5276", linewidth=2.5),
               boxprops=dict(facecolor=BENIGN_COLOR+"55", linewidth=1.5),
               whiskerprops=dict(linewidth=1.5),
               capprops=dict(linewidth=1.5))
    n_outliers = int((data < data.quantile(0.01)).sum() +
                     (data > data.quantile(0.99)).sum())
    ax.set_title(f"{col}\n({n_outliers:,} extreme values outside p1/p99)",
                 fontsize=10, fontweight="bold")
    ax.set_ylabel("log\u2081\u208a(value)  [log-scale]", fontsize=9)
    ax.set_xlabel("(raw feature \u2014 log scale to reveal spread)", fontsize=8)
    ax.set_xticks([])
    ax.grid(axis="y")

fig04.tight_layout()
save_fig(fig04, "04_outlier_boxplots.png", "Outlier Box Plots Before Preprocessing")


# ═════════════════════════════════════════════════════════════════════════════
# 05 — CORRELATION HEATMAP
# ═════════════════════════════════════════════════════════════════════════════
print("[05] Correlation Heatmap...")

corr_features = [
    "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Fwd Packet Length Mean",
    "Flow Duration", "Flow IAT Mean", "Fwd IAT Mean",
    "SYN Flag Count", "ACK Flag Count", "FIN Flag Count", "RST Flag Count",
    "Active Mean", "Idle Mean",
]
corr_features = [c for c in corr_features if c in raw_sample.columns]
corr_data     = raw_sample[corr_features].replace([np.inf, -np.inf], np.nan).dropna()
corr_matrix   = corr_data.corr()

label_map = {
    "Flow Bytes/s"               : "Flow Bytes/s",
    "Flow Packets/s"             : "Flow Pkts/s",
    "Fwd Packets/s"              : "Fwd Pkts/s",
    "Bwd Packets/s"              : "Bwd Pkts/s",
    "Total Fwd Packets"          : "Tot Fwd Pkts",
    "Total Backward Packets"     : "Tot Bwd Pkts",
    "Total Length of Fwd Packets": "Tot Len Fwd",
    "Fwd Packet Length Mean"     : "Fwd Len Mean",
    "Flow Duration"              : "Flow Dur",
    "Flow IAT Mean"              : "IAT Mean",
    "Fwd IAT Mean"               : "Fwd IAT Mean",
    "SYN Flag Count"             : "SYN",
    "ACK Flag Count"             : "ACK",
    "FIN Flag Count"             : "FIN",
    "RST Flag Count"             : "RST",
    "Active Mean"                : "Active Mean",
    "Idle Mean"                  : "Idle Mean",
}
short_labels = [label_map.get(c, c) for c in corr_features]

mask = np.triu(np.ones_like(corr_matrix, dtype=bool), k=1)
fig05, ax05 = plt.subplots(figsize=(14, 12))
fig05.suptitle("Correlation Between Input Signals\n(Pearson r \u2014 Raw Features, Wednesday Sample)",
               fontsize=15, fontweight="bold")
cmap = sns.diverging_palette(220, 10, as_cmap=True)
sns.heatmap(corr_matrix, mask=mask, cmap=cmap, center=0, vmin=-1, vmax=1,
            annot=True, fmt=".2f", linewidths=0.5, linecolor="white",
            square=True, xticklabels=short_labels, yticklabels=short_labels,
            ax=ax05, cbar_kws={"shrink": 0.7, "label": "Pearson r"},
            annot_kws={"size": 8})
ax05.set_xticklabels(ax05.get_xticklabels(), rotation=45, ha="right", fontsize=10)
ax05.set_yticklabels(ax05.get_yticklabels(), rotation=0, fontsize=10)
fig05.tight_layout()
save_fig(fig05, "05_correlation_heatmap.png", "Correlation Heatmap")


# ═════════════════════════════════════════════════════════════════════════════
# 06 — BEFORE vs AFTER PREPROCESSING
# ═════════════════════════════════════════════════════════════════════════════
print("[06] Before vs After Preprocessing...")

SHOW_FEATURES_06 = [
    ("Flow Bytes/s",          "Flow Bytes/s",       "bytes/s",  "log\u2081\u208a(bytes/s)"),
    ("Flow Duration",         "Flow Duration",      "us",       "log\u2081\u208a(us)"),
    ("Total Fwd Packets",     "Total Fwd Packets",  "packets",  "log\u2081\u208a(packets)"),
    ("Fwd Packet Length Mean","Fwd Pkt Len Mean",   "bytes",    "log\u2081\u208a(bytes)"),
]

n_feat = len(SHOW_FEATURES_06)
fig06, axes06 = plt.subplots(n_feat, 2, figsize=(15, 4 * n_feat))
fig06.suptitle("Effect of Data Preprocessing\n"
               "(Left: Raw Values | Right: log\u2081\u208a Transformed Values)",
               fontsize=15, fontweight="bold", y=1.01)

for row_idx, (col, title, unit_raw, unit_proc) in enumerate(SHOW_FEATURES_06):
    ax_raw  = axes06[row_idx, 0]
    ax_proc = axes06[row_idx, 1]

    raw_col  = raw_sample[col].dropna().clip(lower=0)
    proc_col = proc_sample[col].dropna()
    raw_clipped = raw_col.clip(upper=raw_col.quantile(0.99) * 1.1)

    ax_raw.hist(raw_clipped, bins=60, color=BENIGN_COLOR, edgecolor="white",
                linewidth=0.3, alpha=0.85, density=True)
    try:
        raw_clipped.plot.kde(ax=ax_raw, color="#1A5276", linewidth=2)
    except Exception:
        pass
    ax_raw.set_title(f"RAW: {title}", fontsize=11, fontweight="bold", color="#1A5276")
    ax_raw.set_xlabel(f"Value ({unit_raw}) \u2014 capped at p99", fontsize=9)
    ax_raw.set_ylabel("Density", fontsize=9)
    ax_raw.xaxis.set_major_formatter(
        matplotlib.ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    ax_raw.grid(axis="y")

    ax_proc.hist(proc_col, bins=60, color=LOG1P_COLOR, edgecolor="white",
                 linewidth=0.3, alpha=0.85, density=True)
    try:
        proc_col.plot.kde(ax=ax_proc, color="#1B5E20", linewidth=2)
    except Exception:
        pass
    ax_proc.set_title(f"PREPROCESSED: log\u2081\u208a({title})", fontsize=11,
                      fontweight="bold", color="#1B5E20")
    ax_proc.set_xlabel(f"Transformed value ({unit_proc})", fontsize=9)
    ax_proc.set_ylabel("Density", fontsize=9)
    ax_proc.grid(axis="y")

fig06.tight_layout()
save_fig(fig06, "06_before_after_preprocessing.png", "Before vs After Preprocessing")


# ═════════════════════════════════════════════════════════════════════════════
# 09 — ROLLING STATISTICS / ADAPTIVE THRESHOLDING
# ═════════════════════════════════════════════════════════════════════════════
print("[09] Rolling Statistics Visualization...")

ROLL_COLS = [
    ("Flow Bytes/s",   "Flow Bytes/s  (log\u2081\u208a)"),
    ("Flow Packets/s", "Flow Packets/s (log\u2081\u208a)"),
]
SLICE_N  = 2000
ROLL_WIN = 100

fig09, axes09 = plt.subplots(len(ROLL_COLS), 1, figsize=(16, 10), sharex=False)
fig09.suptitle("Signal with Rolling Mean and Rolling Standard Deviation\n"
               "(Adaptive Self-Tuning Threshold Bands \u2014 Preprocessed Streaming Data)",
               fontsize=15, fontweight="bold", y=1.01)

for ax09, (col, label) in zip(axes09, ROLL_COLS):
    slice_data = proc_df[col].iloc[:SLICE_N].reset_index(drop=True)
    roll_mean  = slice_data.rolling(window=ROLL_WIN, center=True, min_periods=5).mean()
    roll_std   = slice_data.rolling(window=ROLL_WIN, center=True, min_periods=5).std()
    upper_band = roll_mean + 2 * roll_std
    lower_band = (roll_mean - 2 * roll_std).clip(lower=0)
    x_idx      = np.arange(len(slice_data))

    ax09.plot(x_idx, slice_data, color="#AEC6E8", linewidth=0.8, alpha=0.7,
              label="Signal (log\u2081\u208a)", zorder=1)
    ax09.plot(x_idx, roll_mean, color=BENIGN_COLOR, linewidth=2.2,
              label=f"Rolling Mean (w={ROLL_WIN})", zorder=3)
    ax09.fill_between(x_idx, lower_band, upper_band, color="#F7B731",
                      alpha=0.25, label="\u00b1 2\u03c3 Adaptive Band", zorder=2)
    ax09.plot(x_idx, upper_band, color="#E65100", linewidth=1.2,
              linestyle="--", label="Upper Threshold (+2\u03c3)", zorder=4)
    ax09.plot(x_idx, lower_band, color="#1B5E20", linewidth=1.0,
              linestyle=":", label="Lower Threshold (\u22122\u03c3, clipped)", zorder=4)

    exceed_mask = slice_data > upper_band
    ax09.scatter(x_idx[exceed_mask], slice_data[exceed_mask],
                 s=18, color=ATTACK_COLOR, zorder=5,
                 label=f"Exceeds Upper Threshold ({exceed_mask.sum()} flows)")
    ax09.set_title(label, fontsize=12, fontweight="bold")
    ax09.set_xlabel("Flow Index (time-ordered within file)", fontsize=10)
    ax09.set_ylabel("log\u2081\u208a(value)", fontsize=10)
    ax09.legend(loc="upper right", fontsize=9, frameon=True)
    ax09.grid(axis="y")

fig09.tight_layout()
save_fig(fig09, "09_rolling_statistics.png",
         "Rolling Statistics / Adaptive Threshold Visualization")


# ═════════════════════════════════════════════════════════════════════════════
# 10 — FINAL PREPROCESSED MULTI-SIGNAL DATASET
# ═════════════════════════════════════════════════════════════════════════════
print("[10] Final Preprocessed Multi-Signal Dataset...")

final_signals = {
    "Flow Bytes/s\n(log\u2081\u208a)"         : "Flow Bytes/s",
    "Flow Packets/s\n(log\u2081\u208a)"       : "Flow Packets/s",
    "Flow Duration\n(log\u2081\u208a)"        : "Flow Duration",
    "Total Fwd Packets\n(log\u2081\u208a)"    : "Total Fwd Packets",
    "Fwd Pkt Len Mean\n(log\u2081\u208a)"     : "Fwd Packet Length Mean",
    "Flow IAT Mean\n(log\u2081\u208a)"        : "Flow IAT Mean",
}

FINAL_SLICE    = 3000
final_slice_df = proc_df.iloc[:FINAL_SLICE].reset_index(drop=True)

fig10, axes10 = plt.subplots(3, 2, figsize=(16, 13))
fig10.suptitle("Preprocessed Data Used for Anomaly Detection\n"
               "(log\u2081\u208a Transformed Signals \u2014 Coloured by Ground-Truth Label)",
               fontsize=16, fontweight="bold", y=1.01)

for ax, (ylabel, col) in zip(axes10.flat, final_signals.items()):
    if col not in final_slice_df.columns:
        ax.set_visible(False)
        continue
    x_idx        = np.arange(len(final_slice_df))
    benign_mask  = (final_slice_df["is_anomaly"] == 0)
    attack_mask  = (final_slice_df["is_anomaly"] == 1)
    ax.scatter(x_idx[benign_mask], final_slice_df.loc[benign_mask, col],
               s=1.5, color=BENIGN_COLOR, alpha=0.5, label="BENIGN", rasterized=True)
    ax.scatter(x_idx[attack_mask], final_slice_df.loc[attack_mask, col],
               s=6, color=ATTACK_COLOR, alpha=0.8, label="Attack",
               rasterized=True, zorder=3)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.set_xlabel("Flow Index", fontsize=10)
    ax.set_title(col, fontsize=11, fontweight="bold")
    ax.grid(axis="y")

handles10 = [
    mpatches.Patch(color=BENIGN_COLOR, label="BENIGN Traffic"),
    mpatches.Patch(color=ATTACK_COLOR, label="Attack Traffic"),
]
fig10.legend(handles=handles10, loc="lower center", ncol=2,
             bbox_to_anchor=(0.5, -0.03), fontsize=11, frameon=True)
fig10.tight_layout()
save_fig(fig10, "10_final_preprocessed_data.png",
         "Final Preprocessed Multi-Signal Dataset")


# ═════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 72)
print("ESSENTIAL 6 PREPROCESSING GRAPHS GENERATED SUCCESSFULLY")
print("=" * 72)
print(f"\nDataset        : CSE-CIC-IDS2018")
print(f"Raw rows       : 2,830,743")
print(f"Final rows     : 2,572,640  (9.12% removed during cleaning)")
print(f"Raw columns    : 79")
print(f"Modeling feats : 63 (across 5 signal groups)")
print(f"Missing NaN    : 1,358  (Flow Bytes/s only) -- all removed")
print(f"Duplicates     : 256,479 -- all removed")
print(f"Outliers       : Extreme in all Rate/Volume/IAT features")
print(f"Scaling used   : log1p on 47 features (NOT StandardScaler)")
print(f"Rolling stats  : Rolling mean +/- 2*std for self-tuning thresholds")
print(f"\nOutput location: {OUT_DIR}")
print(f"\nFiles present in output folder:")
for f in sorted(OUT_DIR.iterdir()):
    size_kb = f.stat().st_size / 1024
    print(f"  {f.name:<55} ({size_kb:>7.1f} KB)")

print("\nDone. All 6 essential graphs and explanations are ready for your PPT presentation.")
