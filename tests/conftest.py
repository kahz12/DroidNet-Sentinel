"""
Project-level pytest config: ensures `import droidnet...` works regardless
of where pytest is invoked from, without requiring an installed package.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
