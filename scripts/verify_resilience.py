"""Disposable Compose fault test: slow database, concurrent agents, service crash.

Run only against a test stack. --allow-faults explicitly enables database locks
and killing/restarting VectorAnchor. Reports contain no response content.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
from run_local_demo import ROOT, load_env, post
from verify_session import get


def compose(*args, **kwargs):
    return subprocess.run(['docker', 'compose', *args], cwd=ROOT, check=True,
                          capture_output=True, text=True, timeout=60, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-faults', action='store_true', required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'evaluation/results/resilience.json')
    args = parser.parse_args()
    env = load_env(ROOT / '.env', dict(os.environ))
    session = 'load-' + uuid.uuid4().hex
    env.update(MONOLITH_SESSION_ID=session, MONOLITH_AGENT_ID='resilience-probe')
    lock = subprocess.Popen(['docker', 'compose', 'exec', '-T', 'database', 'psql',
        '-U', 'postgres', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c',
        "BEGIN; LOCK TABLE monolith.security_events IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(5); COMMIT;"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    # Wait for the actual lock, not an assumed startup delay.
    try:
        for _ in range(50):
            held = compose('exec', '-T', 'database', 'psql', '-U', 'postgres', '-d', 'postgres', '-tAc',
                "SELECT count(*) FROM pg_locks WHERE relation='monolith.security_events'::regclass AND mode='AccessExclusiveLock' AND granted")
            if int(held.stdout.strip()) > 0:
                break
            time.sleep(.05)
        else:
            raise RuntimeError('Failed to establish the slow-database condition')
        def retrieve(index):
            before = time.perf_counter()
            post('http://127.0.0.1:8001/retrieve', {'query': f'Garden advice {index}'}, context=env)
            return (time.perf_counter()-before)*1000
        with ThreadPoolExecutor(max_workers=8) as pool:
            latencies = list(pool.map(retrieve, range(32)))
        if lock.wait(timeout=15):
            raise RuntimeError('Database lock process failed')
    finally:
        if lock.poll() is None:
            lock.terminate()
            lock.wait(timeout=10)
    compose('kill', '-s', 'SIGKILL', 'vector-anchor')
    compose('up', '-d', '--wait', 'vector-anchor')
    retrieve(33)
    # Delivery is at least once; persisted event IDs must remain unique.
    for _ in range(60):
        events = get('http://127.0.0.1:3000/api/incidents?status=all&limit=500&session='+session,
                     env['MONOLITH_OPERATOR_TOKEN'])['incidents']
        retrievals = [e for e in events if e['event_type'] == 'retrieval']
        if len(retrievals) == 33:
            break
        time.sleep(.5)
    else:
        raise RuntimeError('Events were lost across database delay or service crash')
    if len({e['event_id'] for e in retrievals}) != 33:
        raise RuntimeError('Duplicate ledger event IDs')
    result = {'requests': 33, 'concurrency': 8, 'database_lock_seconds': 5,
              'service_crash_recovered': True, 'persisted_unique_events': 33,
              'request_p95_ms': sorted(latencies)[int(.95*(len(latencies)-1))],
              'session_id': session}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
