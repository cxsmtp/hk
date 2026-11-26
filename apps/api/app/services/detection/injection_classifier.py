"""A small offline statistical prompt-injection classifier: naive Bayes over word, word-pair and character 4-gram
features, calibrated with Platt scaling on leave-one-out scores.

It is trained in-process, on first use, from the labelled corpus committed next to this file
(``data/prompt_injection_training.jsonl``): pure Python, no randomness, so the same corpus always gives the same model
(``MODEL_VERSION`` names the corpus by its hash). Long texts are scored in overlapping windows and the highest window
wins, so one injected paragraph inside a long benign document is still seen.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from dataclasses import dataclass
from pathlib import Path

ALGORITHM = "nb-char4-wordbigram-platt-v1"
CORPUS_PATH = Path(__file__).with_name("data") / "prompt_injection_training.jsonl"

_WORD_RE = re.compile(r"[^\W_]+|[<>\[\]{}|#`*=]+", re.UNICODE)
_ALPHA = 0.5
_WINDOW_WORDS = 48
_STRIDE_WORDS = 24
_MAX_WINDOWS = 64


def _words(text: str) -> list[str]:
    return _WORD_RE.findall(text.casefold())


def features(words: list[str]) -> set[str]:
    feats: set[str] = {f"w:{w}" for w in words}
    feats.update(f"b:{a} {b}" for a, b in zip(words, words[1:]))
    joined = f" {' '.join(words)} "
    feats.update(f"c:{joined[i:i + 4]}" for i in range(len(joined) - 3))
    return feats


def windows(text: str) -> list[list[str]]:
    words = _words(text)
    if len(words) <= _WINDOW_WORDS:
        return [words] if words else []
    out = []
    for start in range(0, len(words), _STRIDE_WORDS):
        chunk = words[start : start + _WINDOW_WORDS]
        if len(chunk) < 4 and out:
            break
        out.append(chunk)
        if len(out) >= _MAX_WINDOWS or start + _WINDOW_WORDS >= len(words):
            break
    return out


@dataclass(frozen=True)
class Model:
    log_ratio: dict[str, float]  # log P(f|injection) - log P(f|benign)
    prior: float
    slope: float
    intercept: float
    version: str
    samples: int
    positives: int

    def _z(self, words: list[str]) -> float:
        known = [self.log_ratio[f] for f in features(words) if f in self.log_ratio]
        if not known:
            return self.prior
        return (self.prior + sum(known)) / math.sqrt(len(known))

    def probability(self, words: list[str]) -> float:
        return _sigmoid(self.slope * self._z(words) + self.intercept)

    def score(self, text: str) -> float:
        best = 0.0
        for chunk in windows(text):
            best = max(best, self.probability(chunk))
        return round(best, 4)


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


def load_corpus(path: Path = CORPUS_PATH) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            rows.append((str(item["text"]), 1 if int(item["label"]) else 0))
    return rows


def train(rows: list[tuple[str, int]], *, version: str = "custom") -> Model:
    docs = [(features(_words(text)), label) for text, label in rows]
    n = [0, 0]
    counts: list[dict[str, int]] = [{}, {}]
    for feats, label in docs:
        n[label] += 1
        bucket = counts[label]
        for f in feats:
            bucket[f] = bucket.get(f, 0) + 1
    if not n[0] or not n[1]:
        raise ValueError("the corpus needs both injection and benign examples")
    vocab = set(counts[0]) | set(counts[1])

    def ratio(f: str, c1: int, n1: int, c0: int, n0: int) -> float:
        return math.log((c1 + _ALPHA) / (n1 + 2 * _ALPHA)) - math.log((c0 + _ALPHA) / (n0 + 2 * _ALPHA))

    log_ratio = {f: ratio(f, counts[1].get(f, 0), n[1], counts[0].get(f, 0), n[0]) for f in vocab}
    # Drop features that say nothing, to keep the model small and scoring fast.
    log_ratio = {f: round(v, 5) for f, v in log_ratio.items() if abs(v) >= 0.15}
    prior = math.log(n[1] / n[0])

    # Leave-one-out scores for calibration: each document scored by a model that has not seen it.
    zs: list[float] = []
    labels: list[int] = []
    for feats, label in docs:
        c_n = [n[0] - (label == 0), n[1] - (label == 1)]
        total = 0.0
        known = 0
        for f in feats:
            if f not in log_ratio:
                continue
            c1 = counts[1].get(f, 0) - (1 if label == 1 else 0)
            c0 = counts[0].get(f, 0) - (1 if label == 0 else 0)
            if c1 + c0 <= 0:
                continue
            total += ratio(f, c1, c_n[1], c0, c_n[0])
            known += 1
        loo_prior = math.log(max(1, c_n[1]) / max(1, c_n[0]))
        zs.append((loo_prior + total) / math.sqrt(known) if known else loo_prior)
        labels.append(label)

    slope, intercept = _platt(zs, labels)
    return Model(log_ratio, prior, slope, intercept, version, len(rows), n[1])


def _platt(zs: list[float], labels: list[int], *, iterations: int = 400, rate: float = 0.05) -> tuple[float, float]:
    # Platt's smoothed targets, plain gradient descent from a fixed start: deterministic.
    pos = sum(labels)
    neg = len(labels) - pos
    hi, lo = (pos + 1) / (pos + 2), 1 / (neg + 2)
    targets = [hi if y else lo for y in labels]
    a, b = 1.0, 0.0
    m = len(zs)
    for _ in range(iterations):
        grad_a = grad_b = 0.0
        for z, t in zip(zs, targets):
            p = _sigmoid(a * z + b)
            grad_a += (p - t) * z
            grad_b += p - t
        a -= rate * grad_a / m * 10
        b -= rate * grad_b / m * 10
    return round(a, 6), round(b, 6)


_MODEL: Model | None = None
_LOCK = threading.Lock()


def corpus_version(path: Path = CORPUS_PATH) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def model() -> Model:
    global _MODEL
    if _MODEL is None:
        with _LOCK:
            if _MODEL is None:
                _MODEL = train(load_corpus(), version=f"{ALGORITHM}:{corpus_version()}")
    return _MODEL


def score(text: str) -> float:
    if not text or not text.strip():
        return 0.0
    return model().score(text)
