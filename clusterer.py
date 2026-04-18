import math
from dataclasses import dataclass, field
from ingestor import LogEntry


SEVERITY_KEYWORDS = {
    "critical": ["mimikatz", "lsass", "credential", "dump", "privilege", "escalat", "rootkit", "ransomware"],
    "high":     ["failed password", "brute", "invalid user", "unauthorized", "exploit", "payload",
                 "reverse shell", "c2", "beacon", "exfil", "malware", "backdoor"],
    "medium":   ["scan", "probe", "reject", "block", "deny", "suspicious", "anomal", "lateral"],
    "low":      ["warn", "timeout", "retry", "disconnect"],
}


def _score_severity(entries: list[LogEntry]) -> str:
    text = " ".join(e.message.lower() for e in entries)
    for level, keywords in SEVERITY_KEYWORDS.items():
        if any(k in text for k in keywords):
            return level
    return "info"


@dataclass
class Cluster:
    id: int
    entries: list[LogEntry] = field(default_factory=list)
    label: str = ""
    top_terms: list[str] = field(default_factory=list)
    severity: str = "info"

    @property
    def size(self) -> int:
        return len(self.entries)

    @property
    def sample(self) -> str:
        return self.entries[0].message if self.entries else ""

    @property
    def unique_ips(self) -> set[str]:
        return {e.source_ip for e in self.entries if e.source_ip}


def _tokenize(text: str) -> list[str]:
    import re
    tokens = re.findall(r"[a-zA-Z]{3,}", text.lower())
    STOPWORDS = {"the", "and", "for", "are", "was", "not", "with", "from",
                 "that", "this", "has", "have", "been", "its", "but", "they"}
    return [t for t in tokens if t not in STOPWORDS]


def _tfidf_matrix(docs: list[str]) -> tuple[list[list[float]], list[str]]:
    tokenized = [_tokenize(d) for d in docs]
    vocab = sorted({t for tokens in tokenized for t in tokens})
    vocab_idx = {t: i for i, t in enumerate(vocab)}
    n = len(docs)

    df = [0] * len(vocab)
    for tokens in tokenized:
        for t in set(tokens):
            if t in vocab_idx:
                df[vocab_idx[t]] += 1

    idf = [math.log((n + 1) / (d + 1)) + 1 for d in df]

    matrix = []
    for tokens in tokenized:
        tf = [0.0] * len(vocab)
        for t in tokens:
            if t in vocab_idx:
                tf[vocab_idx[t]] += 1
        norm = sum(v ** 2 for v in tf) ** 0.5 or 1.0
        row = [(tf[i] / norm) * idf[i] for i in range(len(vocab))]
        matrix.append(row)

    return matrix, vocab


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x ** 2 for x in a) ** 0.5
    nb = sum(x ** 2 for x in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


def _kmeans(matrix: list[list[float]], k: int, max_iter: int = 20) -> list[int]:
    import random
    random.seed(42)
    n = len(matrix)
    k = min(k, n)
    centroids = [matrix[i] for i in random.sample(range(n), k)]
    labels = [0] * n

    for _ in range(max_iter):
        new_labels = []
        for vec in matrix:
            sims = [_cosine(vec, c) for c in centroids]
            new_labels.append(sims.index(max(sims)))

        if new_labels == labels:
            break
        labels = new_labels

        for ci in range(k):
            members = [matrix[i] for i, l in enumerate(labels) if l == ci]
            if members:
                centroids[ci] = [
                    sum(members[j][d] for j in range(len(members))) / len(members)
                    for d in range(len(matrix[0]))
                ]

    return labels


def cluster(entries: list[LogEntry], n_clusters: int = 10) -> list[Cluster]:
    if not entries:
        return []

    docs = [e.message for e in entries]
    matrix, vocab = _tfidf_matrix(docs)
    labels = _kmeans(matrix, k=n_clusters)

    clusters: dict[int, Cluster] = {}
    for i, label in enumerate(labels):
        if label not in clusters:
            clusters[label] = Cluster(id=label)
        clusters[label].entries.append(entries[i])

    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

    for cid, cl in clusters.items():
        doc_indices = [i for i, l in enumerate(labels) if l == cid]
        term_scores = {}
        for idx in doc_indices:
            for j, term in enumerate(vocab):
                term_scores[term] = term_scores.get(term, 0) + matrix[idx][j]
        cl.top_terms = sorted(term_scores, key=term_scores.get, reverse=True)[:5]
        cl.severity = _score_severity(cl.entries)

    return sorted(
        clusters.values(),
        key=lambda c: (SEVERITY_ORDER.index(c.severity), -c.size)
    )
