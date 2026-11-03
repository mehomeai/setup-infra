#!/usr/bin/env python3
"""Check the bootstrap repository contract and accidental credential file commits.

This is repository hygiene, not application validation or a full secret scanner.
"""
from pathlib import Path
import subprocess
import sys

required = ('README.md', 'LICENSE', '.github/CODEOWNERS', '.github/workflows/ci.yml')
errors = [f'Missing or empty file: {name}' for name in required
          if not Path(name).is_file() or not Path(name).read_text().strip()]
tracked = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
for name in filter(None, tracked):
    p = Path(name)
    if p.name == '.env' or (p.name.startswith('.env.') and
                            p.suffix not in ('.example', '.sample', '.template')):
        errors.append(f'Remove tracked environment secrets file: {name}')
    if p.name in ('id_rsa', 'id_ed25519') or p.suffix in ('.p12', '.pfx', '.key'):
        errors.append(f'Remove tracked private key file: {name}')
    try:
        content = p.read_text()
    except (UnicodeDecodeError, OSError):
        continue
    if any(line.startswith(('<<<<<<< ', '>>>>>>> ')) for line in content.splitlines()):
        errors.append(f'Unresolved merge conflict: {name}')
if errors:
    print('\n'.join(errors), file=sys.stderr)
    sys.exit(1)
print('Repository health checks passed. Add application tests when code is introduced.')
