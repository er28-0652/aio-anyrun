import hashlib
import json
import string
import random
import typing as t
from websocket import create_connection

import .const as cst

def generate_token(n=8) -> str:
    letters = string.ascii_lowercase + '1234567890'
    return ''.join(random.choice(letters) for _ in range(n))

def generate_id() -> int:
    return random.randint(100, 999)



class AnyRunError(Exception):
    pass

class AnyRunClient:
    def __init__(self):
        self.ws = create_connection(
            f'wss://app.any.run/sockjs/{generate_id()}/{generate_token()}/websocket')
        self._init_connection()
        self._task_id = 0
        self.login_info = None
    
    def send_message(self, msg: dict):
        self.ws.send(json.dumps([json.dumps(msg)]))

    def _init_connection(self):
        self.send_message({'msg': 'connect', 'version': '1', 'support': ['1', 'pre2', 'pre1']})

    def subscribe(self, name: str, params: list = None) -> None:
        if not params:
            params = []
        self.send_message({'msg': 'sub', 'id': generate_token(), 'name': name, 'params': params})

    def get_task_id(self):
        self._task_id += 1
        return str(self._task_id)
        
    def recv_message(self):
        r = self.ws.recv()
        if len(r) > 1:
            return json.loads(json.loads(r[1:])[0])
 
    @staticmethod
    def create_params(is_public: bool = True, hash_: str = '', run_type: cst.RUN_TYPES.types = [],
        name: str = '', verdict: cst.VERDICTS.types = [], extensions: cst.EXTENSIONS.types = [], ip: str = '',
        domain: str = '', file_hash: str = '', mitre_id: str = '', suricata_sid: int = 0,
        significant: bool = False, tag: str = '', skip: int = 0) -> dict:
        '''Create parameters for query.
        Args:
            is_public: always True.
            hash_: file hash to query.
            run_type: object type. acceptable 'file' and 'url'.
            name: file name to query.
            verdict: verdict to query. acceptable 'malicious', 'normal' and 'no-threats'.
            extensions: file type to query. acceptable 'exe', 'dll', 'java', 'html', 
                'flash', 'pdf', 'office', 'script', 'email'
            ip: IP address to query.
            significant: sorry idk, but usually False.
            tag: tag names.
            skip: items numbers to skip.
        '''
        
        _run_type = [run_type] if not isinstance(run_type, list) else run_type
        _verdict = [verdict] if not isinstance(verdict, list) else verdict
        _extensions = [extensions] if not isinstance(extensions, list) else extensions

        params = {
            'isPublic': is_public,
            'hash': hash_,
            'runtype': [cst.RUN_TYPES.data.get(rt.lower()) for rt in _run_type],
            'name': name,
            'verdict': [cst.VERDICTS.data.get(v.lower()) for v in _verdict],
            'ext': [cst.EXTENSIONS.data.get(ext.lower()) for ext in _extensions],
            'ip': ip,
            'domain': domain,
            'fileHash': file_hash,
            'mitreId': mitre_id,
            'sid': suricata_sid,
            'significant': significant,
            'tag': tag,
            'skip': skip
        }
        return params
    
    def get_public_tasks(self, **kwargs) -> t.Any:
        '''Get public tasks based on the given query parameters.'''

        params = self.create_params(**kwargs)
        task_id = generate_token(n=17)

        self.send_message(
            {
                'msg': 'sub',
                'name': 'publicTasks',
                'params': [params['skip']+50, params['skip'], params], # only latest 50 items
                'id': task_id
            }
        )
        
        results = []
        while True:   
            msg = self.recv_message()
            
            if msg is None:
                continue

            if msg.get('msg') == 'error':
                raise AnyRunError(f'{msg["reason"]}, offendingMessage={msg["offendingMessage"]}')
                    
            if msg.get('msg') == 'ready' and msg.get('subs') and msg.get('subs')[0] == task_id:
                break
            
            if msg.get('msg') == 'added' and msg.get('collection') == 'tasks':
                results.append(msg.get('fields'))
        return results
    
    def search(self, **kwargs) -> t.Any:
        '''Search tasks based on the given query parameters.'''

        params = self.create_params(**kwargs)
        task_id = generate_id()
        
        self.send_message(
            {
                'msg': 'method',
                'method': 'getTasks',
                'params': [params],
                'id': task_id
            }
        )
        
        while True:
            msg = self.recv_message()
            if msg is None:
                continue

            if msg.get('error') is not None:
                raise AnyRunError(msg['error']['message'])
            
            if msg.get('msg') == 'result' and msg['id'] == task_id:
                return msg['result']

    def logout(self):
        '''Do logout. you should login first.'''

        if self.login_info is not None:
            self.send_message(
                {
                    'msg': 'method',
                    'method': 'logout',
                    'params': [],
                    'id': self.get_task_id()
                }
            )
            self.login_info = None
    
    def login(self, email: str, password: str) -> t.Any:
        '''Do login. will get login token.'''

        if self.login_info is not None:
            return self.login_info
        
        self.send_message(
            {
                'msg': 'method',
                'method': 'login',
                'params': [
                    {
                        'user': {
                            'email': email
                        },
                        'password': {
                            'digest': hashlib.sha256(password.encode('utf-8')).hexdigest(),
                            'algorithm': 'sha-256'
                        }
                    }
                ],
                'id': self.get_task_id()
            }
        )
        
        while True:
            msg = self.recv_message()
            
            if msg is None:
                continue

            if msg.get('msg') == 'added' and msg.get('collection') == 'users':
                self.login_info = msg['fields']
                return self.login_info