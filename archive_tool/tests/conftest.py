"""pytest 公共配置：把项目根目录加入 sys.path，并定位 7z。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SEVEN_ZIP = Path(os.environ.get("APS_TEST_7Z", str(ROOT / "bin" / "7z.exe")))
HAS_7Z = SEVEN_ZIP.is_file()
