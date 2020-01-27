import typing as t
from typing_extensions import Literal

T_RUN_TYPES = t.List[Literal['url', 'file']]
RUN_TYPES = {
    'url': '0',
    'file': '1'
}

T_EXTENSIONS = t.List[Literal['exe', 'dll', 'java', 'html', 'flash', 'pdf', 'office', 'script', 'email']]
EXTENSIONS = {
    'exe': '0',
    'dll': '1',
    'java': '2',
    'html': '3',
    'flash': '4',
    'pdf': '5',
    'office': '6',
    'script': '7',
    'email': '8'
}

T_VERDICTS = t.List[Literal['malicious', 'normal', 'no-threats']]
VERDICTS = {
    'malicious': 2,
    'normal': 1,
    'no-threats': 0
}