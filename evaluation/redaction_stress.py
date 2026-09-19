"""Fragmentation sweep with explicit unsupported-encoding leak reporting."""
import base64
import json
import random
import sys
import time
import urllib.parse
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'trace-audit'))
from src.stream_proxy import PiiStreamBuffer


def run():
    secret = 'AKIAIOSFODNN7EXAMPLE'
    variants = {
        'plain': secret,
        'zero_width': '\u200b'.join(secret),
        'full_width': ''.join(chr(ord(c)+0xFEE0) for c in secret),
        'spaced': ' '.join(secret),
        'base64': base64.b64encode(secret.encode()).decode(),
        'percent_encoded': ''.join(f'%{b:02X}' for b in secret.encode()),
        'hex': secret.encode().hex(),
    }
    rows = []
    for name, value in variants.items():
        for width in (1, 2, 3, 7, 16, 64):
            text = '安全说明: ' + value + ' 完成。'
            buffer = PiiStreamBuffer()
            output = []
            started = time.perf_counter()
            for index in range(0, len(text), width):
                output.extend(t.token for t in buffer.push(text[index:index+width], None).outputs)
            output.extend(t.token for t in buffer.finish().outputs)
            rows.append({'variant': name, 'width': width, 'leaked': value in ''.join(output),
                         'elapsed_ms': (time.perf_counter()-started)*1000})
    rng = random.Random(42)
    benign = ['普通说明: 请定期给番茄浇水。', 'def add(a, b):\n    return a + b\n',
              ' '.join(rng.choice(['garden', 'soil', 'water']) for _ in range(300)), 'x'*1024]
    changed = []
    for text in benign:
        buffer = PiiStreamBuffer()
        output = []
        for char in text:
            output.extend(t.token for t in buffer.push(char, None).outputs)
        output.extend(t.token for t in buffer.finish().outputs)
        changed.append({'chars': len(text), 'changed': ''.join(output) != text})
    supported = {'plain', 'zero_width', 'full_width', 'spaced'}
    failures = [r for r in rows if r['variant'] in supported and r['leaked']]
    result = {'seed': 42, 'supported_failures': len(failures), 'cases': rows,
              'benign_cases': changed,
              'limitations': 'Base64, percent, and hex are measured gaps, not supported protections. Long identifiers intentionally fail closed.'}
    if failures:
        raise AssertionError(json.dumps(failures))
    return result


if __name__ == '__main__':
    path = Path(sys.argv[1] if len(sys.argv)>1 else 'evaluation/results/redaction-stress.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(run(), indent=2)+'\n', encoding='utf-8')
    print(path)
