from ingestor import LogEntry
from clusterer import Cluster


def label_clusters(clusters: list[Cluster], api_key: str) -> list[Cluster]:
    if not api_key or not clusters:
        return clusters
    try:
        from google import genai
        from google.genai import errors as genai_errors
        client = genai.Client(api_key=api_key)

        MODELS = ["gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-flash"]

        for cl in clusters:
            samples = "\n".join(f"  - {e.message[:120]}" for e in cl.entries[:5])
            prompt = f"""You are a SOC analyst. Given these {cl.size} log entries from the same cluster,
give a SHORT label (max 6 words) describing the security event type, and a one-sentence risk summary.

Top terms: {', '.join(cl.top_terms)}
Sample entries:
{samples}

Respond in this exact format:
LABEL: <short label>
RISK: <one sentence>"""

            for model in MODELS:
                try:
                    resp = client.models.generate_content(model=model, contents=prompt)
                    text = resp.text.strip()
                    for line in text.splitlines():
                        if line.startswith("LABEL:"):
                            cl.label = line.replace("LABEL:", "").strip()
                    break
                except genai_errors.ClientError as e:
                    if "404" in str(e):
                        continue
                    cl.label = f"[{', '.join(cl.top_terms[:3])}]"
                    break
                except Exception:
                    cl.label = f"[{', '.join(cl.top_terms[:3])}]"
                    break

            if not cl.label:
                cl.label = f"[{', '.join(cl.top_terms[:3])}]"

    except Exception:
        for cl in clusters:
            cl.label = f"[{', '.join(cl.top_terms[:3])}]"

    return clusters
