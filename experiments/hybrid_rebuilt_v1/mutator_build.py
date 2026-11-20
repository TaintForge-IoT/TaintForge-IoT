"""Build the source-pinned, per-campaign AFL++ adapter without installing it."""
from __future__ import annotations

from pathlib import Path
import subprocess

from .policy import require


def build_mutator(destination):
    destination = Path(destination).absolute()
    require(destination.parent.is_dir() and not destination.exists(),
            'Hybrid mutator must be built inside an existing, new campaign')
    source = Path(__file__).with_name('mutator.c')
    subprocess.run(['cc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fPIC', '-shared', str(source), '-o', str(destination)],
                   check=True, capture_output=True)
    destination.chmod(0o555)
    return destination
