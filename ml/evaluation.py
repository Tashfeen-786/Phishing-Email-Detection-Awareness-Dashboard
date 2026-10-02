"""
ml/evaluation.py
================
Evaluate and COMPARE the three detection strategies on the same held-out test
split:

    1. RULE-ONLY   - the transparent weighted rule engine
    2. ML-ONLY     - the trained scikit-learn model
    3. HYBRID      - weighted blend of the two

    python ml/evaluation.py
    python ml/evaluation.py --rule-threshold 41 --hybrid-threshold 50

WHY THIS SCRIPT EXISTS
----------------------
The project brief is explicit: *"Do not claim that hybrid detection is
automatically more accurate unless actual evaluation proves it."*

This script is that proof - or that disproof. It reuses the exact test rows
recorded in the saved model bundle (``test_email_ids``), so all three
strategies are measured on identical data, and it writes the real numbers to:

    reports/detection_comparison.json
    reports/detection_comparison.csv
    reports/error_analysis.csv            <- every FP and FN, with its reason
    reports/detection_comparison.png

DECISION THRESHOLDS
-------------------
* RULE  : an email counts as "predicted phishing" at a rule score of 41+,
          i.e. the SUSPICIOUS band and above. This is the operating point a SOC
          would actually escalate on, and it is a PROJECT ASSUMPTION.
* ML    : probability >= 0.5 (the model's own saved threshold).
* HYBRID: combined score >= 50.

The script also sweeps the rule threshold across every band boundary so the
cost of each choice is visible rather than assumed.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd

from backend.config import settings
from backend.services import ml_service
from backend.services.analysis_service import analyze_email
from backend.services.preprocessing import preprocess_dataframe
from ml.train_model import evaluate

REPORTS_DIR = PROJECT_ROOT / "reports"

DEFAULT_RULE_THRESHOLD = 41       # SUSPICIOUS band and above
DEFAULT_HYBRID_THRESHOLD = 50


def _plot_comparison(results: Dict[str, Dict[str, Any]], out_path: Path) -> Path:
    """Grouped bar chart: rule vs ML vs hybrid on the same test split."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    strategies = list(results.keys())
    metrics = ["accuracy", "precision", "recall", "f1"]
    colours = ["#3b82f6", "#22c55e", "#f59e0b", "#a855f7"]

    fig, ax = plt.subplots(figsize=(11, 6.2), facecolor="#0b1018")
    x = np.arange(len(strategies))
    width = 0.2
    for i, metric in enumerate(metrics):
        values = [results[s][metric] for s in strategies]
        bars = ax.bar(x + (i - 1.5) * width, values, width, label=metric.capitalize(),
                      color=colours[i], edgecolor="#0b1018", linewidth=0.8)
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + 0.012, f"{value:.3f}",
                    ha="center", fontsize=8, color="#c7d3e0")
    ax.set_xticks(x, strategies)
    ax.set_ylim(0, 1.12)
    ax.set_title("Rule-Based vs Machine Learning vs Hybrid - same held-out test split",
                 fontsize=13, fontweight="bold", color="#e6edf3", pad=14)
    ax.set_ylabel("score", color="#9fb0c0")
    ax.tick_params(colors="#9fb0c0", labelsize=9)
    ax.grid(axis="y", color="#1e2733", linestyle="--", linewidth=0.7)
    ax.set_axisbelow(True)
    ax.set_facecolor("#0f1621")
    for spine in ax.spines.values():
        spine.set_color("#2a3441")
    ax.legend(facecolor="#131c28", edgecolor="#2a3441", labelcolor="#c7d3e0", ncol=4,
              loc="upper center", fontsize=9)
    fig.text(0.5, 0.02,
             "Measured values - no strategy is assumed to be better than another.",
             ha="center", fontsize=8.5, color="#7d8ea1")
    fig.tight_layout(rect=(0, 0.045, 1, 1))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150, facecolor="#0b1018")
    plt.close(fig)
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare rule, ML and hybrid detection.")
    parser.add_argument("--dataset", default=str(settings.DATASET_PATH))
    parser.add_argument("--model", default=str(settings.MODEL_PATH))
    parser.add_argument("--rule-threshold", type=int, default=DEFAULT_RULE_THRESHOLD)
    parser.add_argument("--hybrid-threshold", type=int, default=DEFAULT_HYBRID_THRESHOLD)
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    model_path = Path(args.model)
    if not dataset_path.exists():
        print(f"[error] dataset not found: {dataset_path}. Run data/generate_dataset.py first.")
        return 1
    if not model_path.exists():
        print(f"[error] model not found: {model_path}. Run ml/train_model.py first.")
        return 1

    import joblib
    bundle = joblib.load(model_path)
    test_ids = set(bundle.get("test_email_ids", []))
    if not test_ids:
        print("[error] the model bundle does not record its test split; retrain the model.")
        return 1

    print("=" * 78)
    print("DETECTION STRATEGY COMPARISON  (rule-only vs ML-only vs hybrid)")
    print("=" * 78)
    print(f"  model        : {bundle.get('model_name')} (trained {bundle.get('trained_at')})")
    print(f"  test rows    : {len(test_ids)} (exactly the split held out during training)")
    print(f"  rule cut-off : score >= {args.rule_threshold} counts as 'predicted phishing'")
    print(f"  ML cut-off   : probability >= {bundle.get('decision_threshold', 0.5)}")
    print(f"  hybrid cut-off: combined >= {args.hybrid_threshold}")
    print("-" * 78)

    raw = pd.read_csv(dataset_path)
    df, _ = preprocess_dataframe(raw, verbose=False)
    test_df = df[df["email_id"].isin(test_ids)].reset_index(drop=True)
    print(f"  matched {len(test_df)} test rows in the dataset")

    ml_service.reload_model()

    rows: List[Dict[str, Any]] = []
    for record in test_df.to_dict("records"):
        result = analyze_email(
            sender=str(record.get("sender", "")),
            subject=str(record.get("subject", "")),
            body=str(record.get("body", "")),
            urls=str(record.get("urls", "")),
            attachment_name=str(record.get("attachment_name", "")),
            use_ml=True,
        )
        ml = result["ml_detection"]
        hybrid = result["hybrid_detection"]
        rows.append({
            "email_id": record["email_id"],
            "sender_domain": record.get("sender_domain", ""),
            "subject": str(record.get("subject", ""))[:80],
            "actual": 1 if record["label"] == "PHISHING" else 0,
            "rule_score": result["risk_score"],
            "classification": result["classification"],
            "ml_probability": ml.get("probability"),
            "hybrid_score": hybrid.get("combined_score"),
            "triggered": ", ".join(t["rule"] for t in result["triggered_rules"]) or "-",
        })

    frame = pd.DataFrame(rows)
    y_true = frame["actual"].to_numpy()

    rule_pred = (frame["rule_score"] >= args.rule_threshold).astype(int).to_numpy()
    rule_proba = (frame["rule_score"] / 100.0).to_numpy()

    has_ml = frame["ml_probability"].notna().all()
    if has_ml:
        ml_proba = frame["ml_probability"].astype(float).to_numpy()
        ml_threshold = float(bundle.get("decision_threshold", 0.5))
        ml_pred = (ml_proba >= ml_threshold).astype(int)
        hybrid_score = frame["hybrid_score"].astype(float).to_numpy()
        hybrid_pred = (hybrid_score >= args.hybrid_threshold).astype(int)
        hybrid_proba = hybrid_score / 100.0
    else:
        print("[warn] the ML model produced no probabilities; only the rule engine is evaluated.")

    results: Dict[str, Dict[str, Any]] = {
        "Rule-based": evaluate(y_true, rule_pred, rule_proba),
    }
    if has_ml:
        results["Machine learning"] = evaluate(y_true, ml_pred, ml_proba)
        results["Hybrid"] = evaluate(y_true, hybrid_pred, hybrid_proba)

    for name, metrics in results.items():
        cm = metrics["confusion_matrix"]
        print(f"  {name:18s} acc={metrics['accuracy']:.4f}  P={metrics['precision']:.4f}  "
              f"R={metrics['recall']:.4f}  F1={metrics['f1']:.4f}  "
              f"AUC={metrics['roc_auc']}  FP={cm['false_positive']} FN={cm['false_negative']}")

    best = max(results, key=lambda n: results[n]["f1"])
    print("-" * 78)
    print(f"  Highest F1 on THIS test split: {best} ({results[best]['f1']:.4f})")
    print("  This is a measured result on one synthetic split, not a general claim.")

    # ---- threshold sweep for the rule engine -----------------------------
    sweep = []
    for threshold in (1, 21, 41, 51, 71):
        pred = (frame["rule_score"] >= threshold).astype(int).to_numpy()
        m = evaluate(y_true, pred, rule_proba)
        sweep.append({"rule_threshold": threshold, "accuracy": m["accuracy"],
                      "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
                      "false_positive": m["confusion_matrix"]["false_positive"],
                      "false_negative": m["confusion_matrix"]["false_negative"]})
    print("-" * 78)
    print("  Rule-threshold sweep (shows the precision/recall trade-off explicitly):")
    for s in sweep:
        print(f"    score >= {s['rule_threshold']:3d}  P={s['precision']:.4f}  "
              f"R={s['recall']:.4f}  F1={s['f1']:.4f}  FP={s['false_positive']}  "
              f"FN={s['false_negative']}")

    # ---- error analysis ---------------------------------------------------
    frame["rule_pred"] = rule_pred
    if has_ml:
        frame["ml_pred"] = ml_pred
        frame["hybrid_pred"] = hybrid_pred
    errors = frame[frame["rule_pred"] != frame["actual"]].copy()
    errors["error_type"] = np.where(errors["actual"] == 1, "FALSE NEGATIVE", "FALSE POSITIVE")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    errors.to_csv(REPORTS_DIR / "error_analysis.csv", index=False)
    print("-" * 78)
    print(f"  Rule-engine errors on the test split: {len(errors)} "
          f"({(errors['error_type'] == 'FALSE POSITIVE').sum()} FP, "
          f"{(errors['error_type'] == 'FALSE NEGATIVE').sum()} FN) "
          f"-> reports/error_analysis.csv")

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model_name": bundle.get("model_name"),
        "model_trained_at": bundle.get("trained_at"),
        "test_rows": int(len(frame)),
        "thresholds": {
            "rule": args.rule_threshold,
            "ml": float(bundle.get("decision_threshold", 0.5)),
            "hybrid": args.hybrid_threshold,
            "hybrid_weights": {"rule": settings.HYBRID_RULE_WEIGHT,
                               "ml": settings.HYBRID_ML_WEIGHT},
        },
        "results": results,
        "highest_f1": best,
        "rule_threshold_sweep": sweep,
        "error_counts": {
            "rule_false_positive": int((errors["error_type"] == "FALSE POSITIVE").sum()),
            "rule_false_negative": int((errors["error_type"] == "FALSE NEGATIVE").sum()),
        },
        "interpretation": (
            "All three strategies were scored on the identical held-out test split. The "
            "strategy with the highest F1 here won on ONE synthetic dataset with ONE seed; "
            "that is evidence, not a general law. The rule engine's value is that it explains "
            "itself, which matters to an analyst regardless of which number is higher."
        ),
        "honesty_note": ("Produced by running ml/evaluation.py. No value in this file was "
                         "typed by hand."),
    }
    (REPORTS_DIR / "detection_comparison.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8")
    pd.DataFrame([
        {"strategy": name, **{k: v for k, v in m.items() if k != "confusion_matrix"},
         "true_positive": m["confusion_matrix"]["true_positive"],
         "true_negative": m["confusion_matrix"]["true_negative"],
         "false_positive": m["confusion_matrix"]["false_positive"],
         "false_negative": m["confusion_matrix"]["false_negative"]}
        for name, m in results.items()
    ]).to_csv(REPORTS_DIR / "detection_comparison.csv", index=False)
    _plot_comparison({k: v for k, v in results.items()},
                     REPORTS_DIR / "detection_comparison.png")

    print("-" * 78)
    print("  reports/detection_comparison.json")
    print("  reports/detection_comparison.csv")
    print("  reports/detection_comparison.png")
    print("  reports/error_analysis.csv")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
