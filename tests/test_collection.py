import json
import unittest
from pathlib import Path

from aio_anyrun import collection

TEST_DATA_DIR = Path(__file__).parent  / 'data' 

TESTS = {
    'file': {
        # method => expect
        'run_type': 'file',
        'mime_type': 'application/x-dosexec',
        'file_type': 'PE32 executable (GUI) Intel 80386, for MS Windows',
        'name': 'Scan_Draft-BLs.img.exe',
        'object_uuid': '63bf34af-fb9a-4b4f-b2eb-1950a3a2debe',
        'task_uuid': 'acdcbcf3-4b3a-42ca-aae5-736683b86800',
        'verdict': 'malicious',
        'threat_level': 2
    },
    'url': {
        'run_type': 'url',
        'mime_type': None,
        'file_type': None,
        'name': 'https://tesuya.example.c0m',
        'object_uuid': 'ce070dac-fd23-4060-a1dd-70d40ab215d5',
        'task_uuid': '08d7c9ed-df02-403f-b07d-3ceb9f1ba05f',
        'verdict': 'malicious',
        'threat_level': 2
    },
    'download': {
        'run_type': 'download',
        'mime_type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'file_type': 'Microsoft Word 2007+',
        'name': 'http://tesuya.example.c0m',
        'object_uuid': 'ce242e17-a083-424d-88cd-52f0d7427ac4',
        'task_uuid': '640a15a3-7b2c-4b84-ab4a-fde92f409455',
        'verdict': 'no-threats',
        'threat_level': 0
    }
}


class TestCollection(unittest.TestCase):

    def load_test_json(self, json_path):
        test_json = TEST_DATA_DIR / json_path
        return collection.Task(json.loads(test_json.read_text()))

    def check(self, task, tests):
        for method, expect in tests.items():
            r = getattr(task, method)
            self.assertEqual(r, expect)

    def test_file_type_collection(self):
        tests = TESTS['file']
        task = self.load_test_json('file_task.json')
        self.check(task, tests)
        
    def test_url_type_collection(self):
        tests = TESTS['url']
        task = self.load_test_json('url_task.json')
        self.check(task, tests)

    
    def test_download_type_collection(self):
        tests = TESTS['download']
        task = self.load_test_json('download_task.json')
        self.check(task, tests)