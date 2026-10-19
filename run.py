import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from splunk_mcp_webui.server import main

if __name__ == "__main__":
    main()
