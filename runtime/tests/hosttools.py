"""GNU userland for bootstrap tests on developer hosts.

Bootstrap runs only on Debian/Ubuntu: it uses GNU coreutils, for example
`realpath -m`, `sha256sum`, `mv -T` and `base64 -w0`, and Bash 4.4 or newer.
On macOS, install Homebrew's `bash` and `coreutils`. Importing this module puts
the unprefixed coreutils `gnubin` directory first on PATH for every test
subprocess. Without these tools, tests that run bootstrap code skip instead of
failing.
"""
import os
from pathlib import Path
import shutil
import subprocess
import unittest


def _output(*command):
    try:
        return subprocess.run(command, capture_output=True, text=True).stdout
    except OSError:
        return ''


def _gnu_coreutils():
    return 'GNU coreutils' in _output('realpath', '--version') and shutil.which('sha256sum') is not None


def _modern_bash():
    # macOS ships Bash 3.2. Before 4.4, `set -u` also rejects empty arrays.
    version = _output('bash', '-c', 'echo "${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"').split()
    return len(version) == 2 and all(part.isdigit() for part in version) and tuple(map(int, version)) >= (4, 4)


def _homebrew_gnubin():
    for prefix in (os.environ.get('HOMEBREW_PREFIX', ''), '/opt/homebrew', '/usr/local'):
        if prefix and (gnubin := Path(prefix, 'opt/coreutils/libexec/gnubin')).is_dir():
            return gnubin
    return None


if not _gnu_coreutils() and (_gnubin := _homebrew_gnubin()):
    os.environ['PATH'] = f'{_gnubin}{os.pathsep}{os.environ.get("PATH", "")}'

GNU_USERLAND = _gnu_coreutils() and _modern_bash()
requires_gnu_userland = unittest.skipUnless(
    GNU_USERLAND, 'bootstrap code needs GNU coreutils and Bash 4.4+; on macOS run `brew install bash coreutils`')


def temporary_root(temp):
    """Return a temporary directory without symlinks (macOS /var is one)."""
    return Path(temp.name).resolve()
