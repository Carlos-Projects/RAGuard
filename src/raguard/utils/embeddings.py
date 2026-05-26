"""Embedding utilities for RAG security analysis."""

from __future__ import annotations

import numpy as np


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Compute cosine similarity between two vectors.

    Args:
        a: First vector.
        b: Second vector.

    Returns:
        Cosine similarity score between -1 and 1.
    """
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)

    if a.ndim == 1:
        a = a.reshape(1, -1)
    if b.ndim == 1:
        b = b.reshape(1, -1)

    dot_product = np.dot(a, b.T)
    norm_a = np.linalg.norm(a, axis=1, keepdims=True)
    norm_b = np.linalg.norm(b, axis=1, keepdims=True)

    if norm_a.item() == 0 or norm_b.item() == 0:
        return 0.0

    return float((dot_product / (norm_a * norm_b.T)).flatten()[0])


def normalize_vector(v: np.ndarray) -> np.ndarray:
    """Normalize a vector to unit length.

    Args:
        v: Input vector.

    Returns:
        Normalized vector.
    """
    v = np.asarray(v, dtype=np.float64)
    norm = np.linalg.norm(v)
    if norm == 0:
        return v
    return v / norm


def embedding_distance(a: np.ndarray, b: np.ndarray, metric: str = "cosine") -> float:
    """Compute distance between two embeddings.

    Args:
        a: First embedding.
        b: Second embedding.
        metric: Distance metric (cosine, euclidean).

    Returns:
        Distance score.
    """
    if metric == "cosine":
        return 1.0 - cosine_similarity(a, b)
    elif metric == "euclidean":
        return float(np.linalg.norm(np.asarray(a) - np.asarray(b)))
    else:
        raise ValueError(f"Unknown metric: {metric}")


def detect_embedding_anomaly(
    embeddings: list[np.ndarray], threshold: float = 2.0
) -> list[int]:
    """Detect anomalous embeddings using statistical outlier detection.

    Args:
        embeddings: List of embedding vectors.
        threshold: Z-score threshold for anomaly detection.

    Returns:
        List of indices of anomalous embeddings.
    """
    if len(embeddings) < 3:
        return []

    # Compute pairwise similarities
    n = len(embeddings)
    similarities = np.zeros((n, n))
    for i in range(n):
        for j in range(i + 1, n):
            sim = cosine_similarity(embeddings[i], embeddings[j])
            similarities[i][j] = sim
            similarities[j][i] = sim

    # Compute mean similarity for each embedding
    mean_sims = np.mean(similarities, axis=1)
    std_sims = np.std(mean_sims)

    if std_sims == 0:
        return []

    # Find outliers
    z_scores = np.abs((mean_sims - np.mean(mean_sims)) / std_sims)
    return [int(i) for i, z in enumerate(z_scores) if z > threshold]
