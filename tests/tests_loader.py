import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.loader import load_json


class TestLoader(unittest.TestCase):
    def test_load_json_reads_event(self):
        event = {
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
        }

        with TemporaryDirectory() as temp_directory:
            input_path = Path(temp_directory) / "event.json"
            input_path.write_text(json.dumps(event), encoding="utf-8")

            loaded_event = load_json(input_path)

        self.assertEqual(loaded_event, event)
