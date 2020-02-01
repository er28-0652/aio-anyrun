import typing as t
from typing_extensions import Literal
from dataclasses import dataclass



@dataclass
class AnyRunConsts:
    types: t.Any
    data: dict


RUN_TYPES = AnyRunConsts(
    types=t.List[Literal['url', 'file']],
    data={
        'url': '0',
        'file': '1'
    }
)

EXTENSIONS = AnyRunConsts(
    types=t.List[Literal['exe', 'dll', 'java', 'html', 'flash', 'pdf', 'office', 'script', 'email']],
    data={
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
)

VERDICTS = AnyRunConsts(
    types=t.List[Literal['malicious', 'normal', 'no-threats']],
    data={
        'malicious': 2,
        'normal': 1,
        'no-threats': 0
    }
)

# type of handler for websocket response
HANDLER_FUNC = t.Callable[[], t.Awaitable[dict]]
