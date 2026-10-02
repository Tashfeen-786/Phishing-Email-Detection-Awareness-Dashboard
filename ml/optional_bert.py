"""
ml/optional_bert.py
===================
OPTIONAL transformer (DistilBERT) track - completely separate from the main
project and NOT required for anything to work.

    python ml/optional_bert.py --check       <- tells you if it can run (safe)
    python ml/optional_bert.py --train       <- only if you really want to

READ THIS BEFORE RUNNING
------------------------
The core project deliberately uses TF-IDF with Logistic Regression, Naive Bayes
and Random Forest. That choice is not a limitation, it is the right engineering
decision here:

  * it trains in about one second on a laptop with no GPU,
  * it is fully reproducible from a seed,
  * the coefficients can be inspected and explained to an analyst, and
  * an awareness dashboard has to justify its verdicts, not just produce them.

DistilBERT needs PyTorch (roughly 2-2.5 GB of downloads), plus the pretrained
weights (~250 MB). On a CPU-only machine, fine-tuning on this dataset takes
minutes rather than seconds, and it produces a model that cannot explain
itself. The project brief requires the project to run locally without heavy
hardware, so this module stays OPTIONAL and is never imported by the backend.

If the dependencies are missing, this script exits cleanly with instructions.
It never installs anything by itself.

HONESTY NOTE
------------
No metric from this file appears anywhere in the project's reports or README
unless you run it yourself. There are no placeholder transformer numbers
anywhere in this repository.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

REPORTS_DIR = PROJECT_ROOT / "reports"
MODEL_DIR = PROJECT_ROOT / "models" / "distilbert"

REQUIRED = ["torch", "transformers", "datasets"]
INSTALL_HINT = (
    "pip install torch --index-url https://download.pytorch.org/whl/cpu\n"
    "    pip install transformers datasets accelerate"
)


def check_environment(verbose: bool = True) -> bool:
    """Report whether the optional transformer stack is installed. Installs nothing."""
    import importlib.util
    missing = [m for m in REQUIRED if importlib.util.find_spec(m) is None]
    if verbose:
        print("=" * 74)
        print("OPTIONAL DISTILBERT TRACK - ENVIRONMENT CHECK")
        print("=" * 74)
        for module in REQUIRED:
            state = "MISSING" if module in missing else "installed"
            print(f"  {module:<14} {state}")
        print("-" * 74)
        if missing:
            print("  This optional module cannot run, and that is perfectly fine.")
            print("  The main project is complete and fully trained without it.")
            print("\n  To enable it (large download, CPU-only wheels shown):")
            print(f"    {INSTALL_HINT}")
        else:
            try:
                import torch
                device = "GPU (cuda)" if torch.cuda.is_available() else "CPU only"
                print(f"  torch {torch.__version__} available - device: {device}")
                if not torch.cuda.is_available():
                    print("  Expect several minutes per epoch on CPU.")
            except Exception as exc:                          # pragma: no cover
                print(f"  torch present but not usable: {exc}")
                return False
            print("  Ready. Run:  python ml/optional_bert.py --train")
        print("=" * 74)
    return not missing


def train(epochs: int = 2, batch_size: int = 16, max_length: int = 256,
          seed: int = 42) -> int:
    """Fine-tune DistilBERT on the generated dataset. Only runs on request."""
    if not check_environment(verbose=False):
        print("[error] optional dependencies are not installed.")
        check_environment(verbose=True)
        return 1

    import numpy as np
    import pandas as pd
    import torch
    from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                                 recall_score, roc_auc_score)
    from sklearn.model_selection import train_test_split
    from torch.utils.data import DataLoader, Dataset
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                              get_linear_schedule_with_warmup)

    from backend.config import settings
    from backend.services.preprocessing import preprocess_dataframe

    torch.manual_seed(seed)
    np.random.seed(seed)

    dataset_path = Path(settings.DATASET_PATH)
    if not dataset_path.exists():
        print(f"[error] dataset not found: {dataset_path}")
        print("        run:  python data/generate_dataset.py")
        return 1

    raw = pd.read_csv(dataset_path)
    df, _ = preprocess_dataframe(raw, verbose=False)
    texts = (df["subject"].fillna("") + "\n" + df["body"].fillna("")).tolist()
    labels = (df["label"] == "PHISHING").astype(int).tolist()

    # Same 70/15/15 stratified proportions as the main pipeline.
    x_train, x_tmp, y_train, y_tmp = train_test_split(
        texts, labels, test_size=0.30, random_state=seed, stratify=labels)
    x_val, x_test, y_val, y_test = train_test_split(
        x_tmp, y_tmp, test_size=0.50, random_state=seed, stratify=y_tmp)
    print(f"  split: train={len(x_train)} val={len(x_val)} test={len(x_test)}")

    model_name = "distilbert-base-uncased"
    print(f"  downloading/loading {model_name} ...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    class EmailDataset(Dataset):
        def __init__(self, txts, labs):
            self.enc = tokenizer(txts, truncation=True, padding="max_length",
                                 max_length=max_length, return_tensors="pt")
            self.labs = torch.tensor(labs)

        def __len__(self):
            return len(self.labs)

        def __getitem__(self, i):
            item = {k: v[i] for k, v in self.enc.items()}
            item["labels"] = self.labs[i]
            return item

    train_loader = DataLoader(EmailDataset(x_train, y_train), batch_size=batch_size,
                              shuffle=True)
    test_loader = DataLoader(EmailDataset(x_test, y_test), batch_size=batch_size)

    optimizer = torch.optim.AdamW(model.parameters(), lr=5e-5)
    total_steps = len(train_loader) * epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, 0, total_steps)

    model.train()
    for epoch in range(epochs):
        running = 0.0
        for step, batch in enumerate(train_loader, 1):
            batch = {k: v.to(device) for k, v in batch.items()}
            optimizer.zero_grad()
            out = model(**batch)
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            running += out.loss.item()
            if step % 5 == 0:
                print(f"    epoch {epoch + 1}/{epochs}  step {step}/{len(train_loader)}  "
                      f"loss {running / step:.4f}")

    model.eval()
    probs, preds = [], []
    with torch.no_grad():
        for batch in test_loader:
            labels_batch = batch.pop("labels")
            batch = {k: v.to(device) for k, v in batch.items()}
            logits = model(**batch).logits
            p = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
            probs.extend(p.tolist())
            preds.extend((p >= 0.5).astype(int).tolist())
            del labels_batch

    metrics = {
        "accuracy": round(float(accuracy_score(y_test, preds)), 4),
        "precision": round(float(precision_score(y_test, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, preds, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, preds, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, probs)), 4),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(MODEL_DIR)
    tokenizer.save_pretrained(MODEL_DIR)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": model_name,
        "epochs": epochs,
        "batch_size": batch_size,
        "max_length": max_length,
        "seed": seed,
        "device": str(device),
        "test_metrics": metrics,
        "note": ("Produced by actually running ml/optional_bert.py --train. This file does "
                 "not exist unless you ran it."),
    }
    (REPORTS_DIR / "optional_bert_metrics.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8")

    print("-" * 74)
    for key, value in metrics.items():
        print(f"  {key:<10} {value}")
    print(f"  model saved to {MODEL_DIR}")
    print("  metrics written to reports/optional_bert_metrics.json")
    print("-" * 74)
    print("  Compare these against reports/ml_metrics.json before concluding that the")
    print("  transformer is better: on a small, clean, synthetic dataset it usually is")
    print("  NOT worth the cost, and it cannot explain its verdict to an analyst.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Optional DistilBERT track (not required by the project).")
    parser.add_argument("--check", action="store_true",
                        help="report whether the optional stack is installed")
    parser.add_argument("--train", action="store_true", help="fine-tune DistilBERT")
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.train:
        return train(args.epochs, args.batch_size, args.max_length, args.seed)
    check_environment(verbose=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
