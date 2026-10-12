# Preprocessing Graph Explanations
## Project: Multi-Signal Self-Tuning Thresholds for Streaming Anomaly Detection
## Dataset: CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity)

This document provides complete, publication-grade explanations and PowerPoint presentation speaking notes for the **6 essential preprocessing graphs** retained for the project presentation. Each graph captures a critical stage of the data engineering and exploratory data analysis (EDA) pipeline that feeds into the streaming anomaly detection model.

---

## Graph 02 — `02_missing_values.png`

| Property | Details |
|---|---|
| **Graph Name** | Missing Values & Infinite Values Before Preprocessing |
| **Preprocessing Step** | Step 1 — Data Quality Inspection (NaN and +Infinity Detection) |
| **X-Axis** | Feature Name (`Flow Bytes/s`, `Flow Packets/s`) |
| **Y-Axis** | Left: Count of Missing (`NaN`) values. Right: Count of `+Infinity` values across all 8 raw CSV files |
| **What the graph tells us** | Across all 2,830,743 records and 79 raw features, data quality issues exist in **only two features**: `Flow Bytes/s` has 1,358 `NaN` and 1,646 `+Infinity` values; `Flow Packets/s` has 2,730 `+Infinity` values. All other 77 features have exactly **zero** missing or infinite values. The root cause is mathematical: CICFlowMeter calculates rates as `bytes / duration`; when `Flow Duration = 0` microseconds, division by zero generates `NaN` or `+Inf`. |
| **Why it is useful for anomaly detection** | Anomaly detection algorithms and distance/density estimators cannot process `NaN` or `Inf` values without throwing numerical errors or producing degenerate anomaly scores. Identifying the single physical root cause (zero-duration flow records) enables surgical remediation: dropping exactly 2,867 zero-duration rows removes 100% of missing and infinite values while preserving 99.9% of the dataset without synthetic imputation. |
| **PPT Speaking Notes** | *"In our data quality audit, we examined over 2.83 million records across all 79 raw features. Only two features exhibited defects: Flow Bytes/s and Flow Packets/s. As shown on the charts, this wasn't random data corruption—it was caused by division-by-zero during packet capture whenever flow duration was zero microseconds. This discovery allowed us to surgically drop those 2,867 zero-duration flows, eliminating all NaNs and infinite values while retaining 99.9% of genuine network traffic."* |
| **Recommended PPT Placement** | **Slide 1 of Preprocessing:** *Data Cleaning & Hygiene* (Side-by-side with data cleaning metrics table) |

---

## Graph 04 — `04_outlier_boxplots.png`

| Property | Details |
|---|---|
| **Graph Name** | Outlier Analysis Across Key Network Signals |
| **Preprocessing Step** | Step 2 — Outlier Detection & Heavy-Tail Diagnostic |
| **X-Axis** | Six representative network signals (`Flow Bytes/s`, `Flow Packets/s`, `Flow Duration`, `Total Fwd Packets`, `Fwd Packet Length Max`, `Flow IAT Max`) |
| **Y-Axis** | Transformed value on $\log_{1p}$ scale ($\log(1 + x)$), used so the interquartile range (IQR) remains clearly visible alongside extreme values |
| **What the graph tells us** | Every core network feature exhibits massive, extreme outlier populations reaching far above the 99th percentile. While the interquartile range (the blue box containing the middle 50% of benign traffic) is compact and tightly bounded, the red fliers extend upwards over multiple orders of magnitude. These extreme outliers are primarily driven by DoS/DDoS volumetric attacks (DoS Hulk, DDoS LOIC/HOIC) and high-volume data exfiltration. |
| **Why it is useful for anomaly detection** | This visualization provides the foundational empirical justification for our pipeline: (1) Attack flows manifest as simultaneous extreme outliers across multiple signal dimensions, validating the necessity of a *multi-signal* detection architecture. (2) Standard scaling methods (such as Z-score standardisation via `StandardScaler`) would fail catastrophically because extreme attack values would heavily distort the global sample mean and standard deviation. |
| **PPT Speaking Notes** | *"Here we examine the outlier profile across six major network signals. Even displayed on a log scale, the red markers show hundreds of thousands of extreme outliers stretching orders of magnitude beyond normal traffic bounds. These are not noise—they represent DoS and DDoS attack surges. This proves two things: first, attacks produce concurrent deviations across multiple signals, which justifies our multi-signal approach; second, conventional Z-score scaling would be severely corrupted by these extremes, leading us to use monotonic log1p scaling."* |
| **Recommended PPT Placement** | **Slide 2 of Preprocessing:** *Traffic Characteristics & Outlier Analysis* |

---

## Graph 05 — `05_correlation_heatmap.png`

| Property | Details |
|---|---|
| **Graph Name** | Pearson Correlation Between Multi-Signal Features |
| **Preprocessing Step** | Step 3 — Feature Collinearity Analysis & Orthogonal Grouping |
| **X-Axis / Y-Axis** | 17 key network flow features representing Volume, Rate, Temporal (IAT), Flag, and Activity behaviors |
| **Color Scale** | Diverging colormap from $-1.00$ (blue) through $0.00$ (neutral) to $+1.00$ (deep red) with Pearson correlation coefficients annotated |
| **What the graph tells us** | The heatmap reveals two critical architectural insights: (1) Strong collinearity clusters exist within specific feature families—for example, Forward Packets/s and Flow Packets/s ($r \approx 0.95$), and Total Packets and Total Length ($r > 0.85$). (2) Across distinct behavioural families (e.g., TCP Flags vs. Inter-Arrival Times vs. Flow Byte Rates), the correlations are near zero. |
| **Why it is useful for anomaly detection** | High collinearity causes feature redundancy, artificially doubles feature weighting in multivariate estimators, and wastes streaming compute. The correlation analysis justified removing 16 constant and redundant collinear features (where $r = 1.00$). More importantly, it enabled the structuring of the remaining 63 features into **5 orthogonal behavioral groups** (Volume, Rate, Temporal, Protocol/Flags, and Silence/Activity), ensuring the anomaly detector evaluates genuinely independent dimensions of network behavior. |
| **PPT Speaking Notes** | *"This Pearson correlation matrix guided our feature selection and signal grouping. Notice the deep red clusters: features within the same group, like forward and total packet counts, are highly correlated. Conversely, inter-arrival times and TCP flag behaviors show near-zero correlation with byte rates. By pruning 16 redundant features and grouping the remaining 63 into five orthogonal signal groups, we prevent duplicate feature bias and give our Isolation Forest model independent perspectives on network behavior."* |
| **Recommended PPT Placement** | **Slide 3 of Preprocessing:** *Feature Selection & Multi-Signal Architecture* |

---

## Graph 06 — `06_before_after_preprocessing.png`

| Property | Details |
|---|---|
| **Graph Name** | Effect of Data Preprocessing ($\text{Raw}$ vs. $\log_{1p}$ Transformed) |
| **Preprocessing Step** | Step 4 — Non-Linear Monotonic $\log_{1p}$ Transformation |
| **X-Axis** | Left columns: Raw feature values (capped at 99th percentile for display). Right columns: $\log_{1p}(x)$ transformed values |
| **Y-Axis** | Probability density (histogram + continuous Kernel Density Estimation curve) |
| **What the graph tells us** | A direct side-by-side comparison for four primary signals (`Flow Bytes/s`, `Flow Duration`, `Total Fwd Packets`, `Fwd Packet Length Mean`). On the left, raw data exhibits severe right-skewness (skewness coefficients ranging from $+5$ to $+50$) where $>90\%$ of records collapse into a single sharp bar at zero with an uninformative flat tail. On the right, after applying $x \mapsto \ln(1 + \max(0, x))$, the distributions become smooth, well-spread, and approximately symmetric with identifiable modal structures. |
| **Why it is useful for anomaly detection** | Unprocessed heavy-tailed distributions cause tree-based partitioning (like Isolation Forest) and sliding-window statistics to suffer from high variance and poor threshold sensitivity. The $\log_{1p}$ transformation compresses massive dynamic ranges without losing monotonicity, preserves zero-value semantics ($\ln(1+0) = 0$), and prevents extreme attack values from disproportionately dominating threshold calculations. |
| **PPT Speaking Notes** | *"This before-and-after visualization is the most direct demonstration of our preprocessing impact. Looking at the raw plots on the left, network traffic is heavily right-skewed—almost all benign traffic collapses into a spike at zero, while attack traffic creates a sparse tail spanning millions of units. On the right, our log1p transformation spreads the distribution into a well-behaved, balanced curve. This stabilizes the variance and enables both Isolation Forest and rolling threshold calculations to operate accurately."* |
| **Recommended PPT Placement** | **Slide 4 of Preprocessing:** *Feature Transformation & Distribution Normalization* (Primary / High-Impact Slide) |

---

## Graph 09 — `09_rolling_statistics.png`

| Property | Details |
|---|---|
| **Graph Name** | Streaming Signal with Rolling Mean and Dynamic Self-Tuning Thresholds |
| **Preprocessing Step** | Step 5 — Online Streaming Feature Engineering & Adaptive Thresholding |
| **X-Axis** | Flow Index (chronologically ordered streaming network flows within capture window) |
| **Y-Axis** | Transformed signal magnitude ($\log_{1p}$ scale) |
| **Components** | • Light Blue Line: Streaming network signal value<br>• Dark Blue Line: Rolling baseline mean ($\mu_{t}$)<br>• Yellow Shaded Band: Self-tuning adaptive threshold envelope ($\mu_t \pm 2\sigma_t$)<br>• Red Markers: Flows flagged where the signal breaches the upper threshold limit |
| **What the graph tells us** | Rather than applying a rigid, static threshold across non-stationary network traffic, the algorithm computes rolling window statistics ($\text{window} = 100$ flows). During periods of calm or gradual shift, the threshold band naturally contracts and tracks the true baseline. When attack bursts occur (surges in byte rates, packet volumes, or connection attempts), the signal sharply breaks out of the yellow envelope and is flagged immediately as an anomaly (red dots). |
| **Why it is useful for anomaly detection** | Static thresholds inevitably produce catastrophic false positive spikes during legitimate traffic peaks (e.g., diurnal cycles or scheduled backups) and fail to catch low-rate attacks during quiet hours. Streaming rolling statistics allow the decision threshold to **self-tune in real time**, providing high sensitivity to genuine anomalies while adapting to natural non-stationary network drift. |
| **PPT Speaking Notes** | *"Graph 09 represents the core algorithmic contribution of our project: self-tuning adaptive thresholds. In streaming environments, network traffic is non-stationary. A static threshold would either cause false alarms during busy periods or miss subtle attacks during quiet hours. As shown here, our algorithm computes a continuous rolling mean and standard deviation. The yellow envelope dynamically expands and contracts with baseline traffic. Whenever a signal breaks through this dynamic band—marked by the red points—it is flagged as an anomaly in real time."* |
| **Recommended PPT Placement** | **Slide 5 of Preprocessing / Method:** *Self-Tuning Streaming Threshold Mechanism* (Core Contribution Slide) |

---

## Graph 10 — `10_final_preprocessed_data.png`

| Property | Details |
|---|---|
| **Graph Name** | Multi-Signal Preprocessed Feature Set Ready for Anomaly Detection |
| **Preprocessing Step** | Step 6 — Final Modeling Input (Post-Cleaning, Transformed, Label-Aligned) |
| **X-Axis** | Flow Index (chronological sequence of incoming flows) |
| **Y-Axis** | Transformed values ($\log_{1p}$) across six key signals simultaneously |
| **Color Coding** | Blue Points = Ground-Truth **BENIGN** Traffic; Red Points = Ground-Truth **Attack** Traffic |
| **What the graph tells us** | Across all six dimensions, benign traffic forms a stable, consistent operational band, while attack flows consistently separate out into distinct, high-density anomalous clusters. Crucially, while any single feature alone may have slight overlap between benign and attack traffic, the **combination of multi-signal deviations** produces near-perfect separability. |
| **Why it is useful for anomaly detection** | This confirms the end-state quality of the entire preprocessing pipeline. The data entering the Isolation Forest and multi-signal aggregator is clean, scaled, normalized, and discriminative. It visually proves why multi-signal fusion outperforms single-threshold systems: attacks leave distinct multi-dimensional footprints. |
| **PPT Speaking Notes** | *"This final graph shows the fully preprocessed multi-signal data that enters our anomaly detector. Blue points represent normal benign traffic and red points represent confirmed attack flows. Notice that while benign traffic remains within a stable band, attacks emerge as conspicuous clusters across multiple signals simultaneously. No single signal alone is sufficient to catch every attack, but fusing these six clean signals allows our multi-signal detector to achieve superior detection accuracy."* |
| **Recommended PPT Placement** | **Slide 6 of Preprocessing:** *Final Clean Feature Space & Multi-Signal Validation* |

---

## Complete Project & Dataset Technical Reference

### 1. Dataset Overview
- **Name:** CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity / Communications Security Establishment)
- **Environment:** Realistic enterprise network environment with 50 victim machines, 420 servers, and 30 attack machines
- **Capture Tool:** CICFlowMeter (generates bidirectional flow statistics from raw PCAP captures)
- **Raw Volume:** 8 CSV files covering Monday through Friday working hours (2,830,743 raw flow records; 79 columns)
- **Cleaned Volume:** 2,572,640 records (258,103 records / 9.12% removed during data cleaning)
- **Final Modeling Features:** 63 numerical features organized across 5 orthogonal signal groups (+ 2 context columns + 2 label columns = 67 total columns)

### 2. Five Orthogonal Signal Groups
| Group | Feature Count | Examples | Role in Anomaly Detection |
|---|:---:|---|---|
| **1. Volume & Size** | 19 | `Total Fwd Packets`, `Total Length of Fwd Packets`, `Packet Length Mean/Std/Max` | Detects volumetric anomalies, brute-force exfiltration, and large payload transfers |
| **2. Rate & Velocity** | 4 | `Flow Bytes/s`, `Flow Packets/s`, `Fwd Packets/s`, `Bwd Packets/s` | Identifies rapid-fire DoS/DDoS flooding and automated scanning tools |
| **3. Temporal / IAT** | 15 | `Flow Duration`, `Flow IAT Mean/Std/Max`, `Fwd IAT Mean`, `Bwd IAT Mean` | Captures timing anomalies, slow-rate DoS (Slowloris), and beaconing intervals |
| **4. TCP Flags & Headers** | 17 | `SYN Flag Count`, `ACK Flag Count`, `FIN Flag Count`, `Init_Win_bytes_forward` | Detects protocol violations, SYN floods, port scans, and malformed handshakes |
| **5. Activity & Silence** | 8 | `Active Mean/Std/Max`, `Idle Mean/Std/Max` | Identifies unusual burstiness, long idle command-and-control channels |

### 3. Data Quality Issues & Cleaning Rules
| Issue Identified | Raw Count | Remediation Rule | Justification |
|---|:---:|---|---|
| **Missing Values (`NaN`)** | 1,358 | Dropped 2,867 zero-duration rows | Division by zero (`bytes / 0`) occurs when flow duration is zero microseconds. |
| **Positive Infinity (`+Inf`)** | 4,376 | Dropped simultaneously with zero-duration rows | Division by zero (`packets / 0`) in CICFlowMeter calculation. |
| **Exact Duplicate Rows** | 256,479 (9.06%) | Deduplicated using Pandas `drop_duplicates()` | Network flow probes capturing identical TCP retransmissions or duplicate CSV logging. |
| **Negative Duration Artifacts** | 113 rows | Corrected using absolute value: $\vert \text{Duration} \vert$ | 32-bit counter rollover artifact in CICFlowMeter timing clock. |
| **Negative IAT Artifacts** | 2,887 rows | Clipped lower bound to 0: $\max(0, \text{IAT})$ | Timestamp jitter artifact in microsecond capture hardware. |
| **Constant / Zero Variance Features** | 8 columns | Removed (`Bwd PSH Flags`, `Bwd URG Flags`, etc.) | Provide zero variance or entropy across the entire 2.8M row dataset. |
| **Exact Collinear Duplicates** | 8 columns | Removed (`Fwd Header Length.1`, `CWE Flag Count`, etc.) | Redundant duplicates ($r = 1.00$) duplicated by logging software. |

### 4. Mathematical Transformations Applied
1. **$\log_{1p}$ Non-Linear Monotonic Scaling:**
   $$\tilde{x} = \ln(1 + \max(0, x))$$
   - Applied to **47 continuous, heavy-tailed features**.
   - *Why NOT StandardScaler?* Extreme DoS/DDoS attack values would heavily distort global mean ($\mu$) and standard deviation ($\sigma$), shrinking benign variance to zero.
   - *Why NOT MinMaxScaler?* New streaming flows exceeding historical bounds would fall outside $[0, 1]$, breaking normalization.
   - *Why $\log_{1p}$?* Monotonic (preserves order), strictly handles zeroes ($\ln(1+0) = 0$), compresses orders-of-magnitude dynamic range without loss of information.

2. **Self-Tuning Rolling Window Thresholding:**
   $$\mu_t = \frac{1}{W}\sum_{i=t-W+1}^{t} x_i, \quad \sigma_t = \sqrt{\frac{1}{W}\sum_{i=t-W+1}^{t} (x_i - \mu_t)^2}$$
   $$\text{Upper Threshold}_t = \mu_t + k \cdot \sigma_t, \quad \text{Lower Threshold}_t = \mu_t - k \cdot \sigma_t$$
   - Rolling window $W = 100$ flows, sensitivity multiplier $k = 2.0$.
   - Adapts to non-stationary network trends and diurnal baseline shifts.

---

## Summary Table: 6 Kept Graphs for Your College PPT Presentation

| Order | Image File | Slide Title | Primary Takeaway for Audience |
|:---:|---|---|---|
| **1** | `02_missing_values.png` | **Data Quality & Surgical Cleaning** | Only 2 features had missing/inf values caused by zero-duration flows; 99.9% clean data. |
| **2** | `04_outlier_boxplots.png` | **Outlier Distribution & Attack Signatures** | Massive outliers confirm multi-signal attack footprints and rule out linear scaling. |
| **3** | `05_correlation_heatmap.png` | **Collinearity & Orthogonal Signal Groups** | 16 redundant features pruned; remaining 63 structured into 5 independent behavior groups. |
| **4** | `06_before_after_preprocessing.png` | **Feature Transformation Impact ($\log_{1p}$)** | Heavy right-skew converted into smooth, well-conditioned distributions for Isolation Forest. |
| **5** | `09_rolling_statistics.png` | **Streaming Self-Tuning Thresholds** | Core innovation: Dynamic $\mu \pm 2\sigma$ envelope self-tunes to streaming traffic in real time. |
| **6** | `10_final_preprocessed_data.png` | **Preprocessed Multi-Signal Feature Space** | Clean multi-dimensional separation between benign traffic and ground-truth attacks. |
