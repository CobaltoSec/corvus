from pathlib import Path
import pytest

MOCK_SERVER_CMD = ["python", str(Path(__file__).parent / "mock_server.py")]
MUTATING_SERVER_CMD = ["python", str(Path(__file__).parent / "mock_mutating_server.py")]
