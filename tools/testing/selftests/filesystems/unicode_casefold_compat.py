#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Two-kernel test on a disposable, mounted ext4/F2FS directory.

Run prepare on the old kernel, unmount, boot the fixed kernel, mount and
run check.  This program neither formats nor mounts filesystems.  The
provided directory must be empty and must never contain real user data.
Encrypted tests require an unlocked fscrypt policy inherited by this path.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import subprocess


def prepare(root):
    if any(root.iterdir()):
        raise RuntimeError('prepare requires an empty disposable directory')
    cases = []
    for layout, count in [('inline', 0), ('indexed', 4096)]:
        directory = root / layout
        directory.mkdir()
        subprocess.run(['chattr', '+F', str(directory)], check=True)
        for i in range(count):
            (directory / ('filler-%05d' % i)).touch()
        for name, alias in [('legacy-a\u200bb', 'legacy-ab'),
                            ('legacy-a\u200cb', 'legacy-acb'),
                            ('legacy-a\u200db', 'legacy-adb'),
                            ('legacy-a\u00adb', 'legacy-aeb'),
                            ('legacy-\u2764\ufe0f', 'legacy-\u2764'),
                            ('legacy-\u00e4', None)]:
            # Different prefixes keep old-equivalent filenames apart.
            if '\u200c' in name:
                name = name.replace('legacy-', 'joiner-c-')
                alias = name.replace('\u200c', '')
            elif '\u200d' in name:
                name = name.replace('legacy-', 'joiner-d-')
                alias = name.replace('\u200d', '')
            elif '\u00ad' in name:
                name = name.replace('legacy-', 'soft-hyphen-')
                alias = name.replace('\u00ad', '')
            payload = (layout + ':' + name).encode()
            # Verify old equality so this phase cannot silently seed new hashes.
            path = directory / name
            path.write_bytes(payload)
            if alias is not None:
                assert (directory / alias).stat().st_ino == path.stat().st_ino
            cases.append([layout, name, alias, payload.hex()])
    (root / 'manifest.json').write_text(json.dumps(cases, ensure_ascii=True))
    os.sync()
    print('prepared old hashes; unmount before checking with fixed kernel')


def check(root):
    cases = json.loads((root / 'manifest.json').read_text())
    # Delete before any rename can rebuild this entry with a current hash.
    index = next(i for i, case in enumerate(cases) if case[2] is not None)
    layout, name, _, hex_payload = cases.pop(index)
    old_entry = root / layout / name
    assert old_entry.read_bytes() == bytes.fromhex(hex_payload), old_entry
    old_entry.unlink()
    assert not old_entry.exists()
    (root / 'manifest.json').write_text(json.dumps(cases, ensure_ascii=True))
    for layout, name, alias, hex_payload in cases:
        directory = root / layout
        path = directory / name
        payload = bytes.fromhex(hex_payload)
        assert path.read_bytes() == payload, path
        assert name in os.listdir(directory), path
        if alias is not None:
            try:
                (directory / alias).stat()
            except OSError as exc:
                assert exc.errno == errno.ENOENT, exc
            else:
                raise AssertionError('ignorable alias still resolves: ' + alias)
        inode = path.stat().st_ino
        renamed = directory / (name + '-renamed')
        path.rename(renamed)
        assert renamed.read_bytes() == payload
        renamed.rename(path)
        assert path.stat().st_ino == inode
    for layout in ['inline', 'indexed']:
        directory = root / layout
        first, second = directory / 'new-ab', directory / 'new-a\u200bb'
        first.write_bytes(b'plain')
        with second.open('xb') as stream:
            stream.write(b'ignorable')
        assert first.read_bytes() == b'plain'
        assert second.read_bytes() == b'ignorable'
        assert first.stat().st_ino != second.stat().st_ino
        first.unlink()
        second.unlink()
    os.sync()
    print('PASS: exact-name recovery, alias rejection, rename, unlink, new names')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['prepare', 'check'])
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    if not args.directory.is_dir():
        parser.error('directory must already exist on a disposable filesystem')
    (prepare if args.phase == 'prepare' else check)(args.directory)
