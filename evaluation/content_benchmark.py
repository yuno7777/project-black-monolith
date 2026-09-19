"""Score first-hit document indicators against the complete independent test split."""
import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from real_models import summarize, percentile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vector-anchor'))
from src.content_guard import inspect_document


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.dataset.read_text(encoding='utf-8'))
    rows, timings = [], []
    for case in data['cases']:
        started = time.perf_counter()
        indicators = inspect_document(case['prompt'])
        timings.append((time.perf_counter()-started)*1000)
        rows.append({'id': case['id'], 'attack': case['attack'],
                     'detected': bool(indicators), 'indicators': indicators})
    result = {'source': data['source'], 'revision': data['revision'],
              'dataset_sha256': data['sha256'], 'policy': 'vector-anchor/2',
              'policy_sha256': hashlib.sha256(Path(inspect_document.__code__.co_filename).read_bytes()).hexdigest(),
              'summary': summarize(rows), 'p95_ms': percentile(timings, .95), 'cases': rows,
              'limitations': 'Prompt classification proxy for retrieved instruction risk; not end-to-end attack success. Includes quoted-instruction false positives.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result['summary']))


if __name__ == '__main__':
    main()
