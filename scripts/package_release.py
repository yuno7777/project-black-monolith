"""Build a deterministic source release from a committed Git revision."""
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def build(revision, version, output):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?', version):
        raise ValueError('Version must be a semantic version without path separators')
    commit = git('rev-parse', '--verify', revision + '^{commit}').decode().strip()
    entries = git('ls-tree', '-rz', '--full-tree', commit).split(b'\0')
    manifest = {'version': version, 'commit': commit, 'files': {}}
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f'black-monolith-{version}-source.zip'
    prefix = f'black-monolith-{version}/'
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_STORED) as archive:
        for entry in sorted(e for e in entries if e):
            metadata, raw_name = entry.split(b'\t', 1)
            mode, kind, sha = metadata.decode().split()
            name = raw_name.decode('utf-8')
            if kind != 'blob' or mode not in ('100644', '100755'):
                raise ValueError(f'Unsupported release entry: {name}')
            if Path(name).name == '.env' or name.startswith(('evaluation/results/', 'dist/')):
                raise ValueError(f'Unexpected generated or sensitive tracked file: {name}')
            content = git('cat-file', 'blob', sha)
            manifest['files'][name] = hashlib.sha256(content).hexdigest()
            info = zipfile.ZipInfo(prefix + name, (2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = int(mode, 8) << 16
            archive.writestr(info, content)
        info = zipfile.ZipInfo(prefix + 'RELEASE-MANIFEST.json', (2020, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = 0o100644 << 16
        archive.writestr(info, json.dumps(manifest, indent=2, sort_keys=True)+'\n')
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix('.zip.sha256').write_text(f'{digest}  {destination.name}\n', encoding='utf-8')
    return destination, digest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', default='HEAD')
    parser.add_argument('--version', default='0.2.0-rc.1')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    print(build(args.revision, args.version, args.output))
