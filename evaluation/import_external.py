"""Download a pinned independent test split, without executing dataset code."""
import argparse
import hashlib
import json
import urllib.request
from pathlib import Path

REPO = "deepset/prompt-injections"
REVISION = "4f61ecb038e9c3fb77e21034b22511b523772cdd"
FILE = "data/test-00000-of-00001-701d16158af87368.parquet"
URL = f"https://huggingface.co/datasets/{REPO}/resolve/{REVISION}/{FILE}"


def main():
    import pyarrow.parquet as pq
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('evaluation/results/external.json'))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    raw = args.output.with_suffix('.parquet')
    with urllib.request.urlopen(URL, timeout=60) as response:
        body = response.read(2_000_001)
    if len(body) > 2_000_000:
        raise ValueError('Dataset exceeds the expected download bound')
    raw.write_bytes(body)
    rows = pq.read_table(raw).to_pylist()
    if not rows or any(not isinstance(r.get('text'), str) or r.get('label') not in (0, 1) for r in rows):
        raise ValueError('Unexpected external dataset schema')
    cases = [{'id': hashlib.sha256(r['text'].encode()).hexdigest(),
              'prompt': r['text'], 'attack': bool(r['label']), 'category': 'external_test'} for r in rows]
    cases.sort(key=lambda r: r['id'])
    args.output.write_text(json.dumps({
        'source': URL, 'revision': REVISION, 'split': 'test',
        'sha256': hashlib.sha256(body).hexdigest(),
        'attribution': 'deepset/prompt-injections, Hugging Face. Preserve source attribution.',
        'license_metadata': {'top_level': 'Apache-2.0', 'dataset_info': 'CC-BY-4.0'},
        'limitations': 'Upstream license metadata differs by field. Data downloaded separately; not vendored. Never used for calibration.',
        'cases': cases,
    }, indent=2) + '\n', encoding='utf-8')
    print(f'Imported {len(cases)} independent test cases at revision {REVISION}')


if __name__ == '__main__':
    main()
