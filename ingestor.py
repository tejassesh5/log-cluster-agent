import json
import csv
import re
from pathlib import Path
from dataclasses import dataclass


@dataclass
class LogEntry:
    raw: str
    timestamp: str = ""
    source_ip: str = ""
    event_type: str = ""
    message: str = ""


_TS_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"|(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _parse_line(line: str) -> LogEntry:
    entry = LogEntry(raw=line.strip())
    ts = _TS_RE.search(line)
    if ts:
        entry.timestamp = ts.group(0)
    ip = _IP_RE.search(line)
    if ip:
        entry.source_ip = ip.group(1)
    entry.message = line.strip()
    return entry


def load(path: str) -> list[LogEntry]:
    p = Path(path)
    ext = p.suffix.lower()

    if ext == ".json":
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [LogEntry(
                raw=json.dumps(item),
                timestamp=str(item.get("timestamp", item.get("time", item.get("@timestamp", "")))),
                source_ip=str(item.get("src_ip", item.get("source_ip", item.get("clientip", "")))),
                event_type=str(item.get("event_type", item.get("type", item.get("category", "")))),
                message=str(item.get("message", item.get("msg", item.get("event", json.dumps(item))))),
            ) for item in data]

    if ext == ".csv":
        entries = []
        with open(p, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(LogEntry(
                    raw=str(row),
                    timestamp=str(row.get("timestamp", row.get("time", ""))),
                    source_ip=str(row.get("src_ip", row.get("source_ip", ""))),
                    event_type=str(row.get("event_type", row.get("type", ""))),
                    message=str(row.get("message", row.get("msg", str(row)))),
                ))
        return entries

    with open(p, encoding="utf-8", errors="replace") as f:
        return [_parse_line(line) for line in f if line.strip()]
