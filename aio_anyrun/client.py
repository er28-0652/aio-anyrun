import aiohttp
import json
import string
import random
from contextlib import asynccontextmanager

from aio_anyrun import collection
from aio_anyrun import const as cst


def generate_token(n=8) -> str:
    letters = string.ascii_lowercase + '1234567890'
    return ''.join(random.choice(letters) for _ in range(n))

def generate_id() -> str:
    return str(random.randint(100, 999))


class AnyRunError(Exception):
    pass


class AnyRunClient:
    '''
    Usage:
        connect with contextmanager
        ... async with AnyRunClient.connect() as client:
        ...     tasks = await client.get_public_tasks()

        connect by your self (close connection by yourself)
        ... client = AnyRunClient()
        ... await client.init_connection_with_default_client()
        ... tasks = await client.get_public_tasks()
        ... await client.close()
    
    '''

    METHOD_COLLECTION_TABLE = {
        'singleTask': 'tasks',
        'publicTasks': 'tasks',
        'login': 'users',
        'taskexists': 'taskExists'
        
    }

    def __init__(self):
        self.session = aiohttp.ClientSession()
        self.cleint = None
        self._current_token_id = 1
    
    async def _init_client(self, user_agent='', autoclose=True, timeout=30):
        self.client = await self.session.ws_connect(
            f'wss://app.any.run/sockjs/{generate_id()}/{generate_token()}/websocket',
            headers={'User-Agent': user_agent},
            autoclose=autoclose,
            receive_timeout=timeout)
        
    async def _init_connection(self):
        await self._send_message({
            'msg': 'connect',
            'version': '1',
            'support': ['1', 'pre2', 'pre1']})

    async def init_connection_with_default_client(self):
        await self._init_client()
        await self._init_connection()
    
    async def close(self):
        await self.client.close()
        await self.session.close()

    @staticmethod
    @asynccontextmanager
    async def connect(user_agent='', autoclose=True, timeout=30):
        try:
            anyrun = AnyRunClient()
            await anyrun._init_client(user_agent, autoclose, timeout)
            await anyrun._init_connection()
            yield anyrun
            
        finally:
            await anyrun.close()

    @property
    def _task_id(self):
        c_token = self._current_token_id
        self._current_token_id += 1
        return c_token
    
    async def _send_message(self, msg):
        await self.client.send_json([json.dumps(msg)])
        
    async def send_message(self, name, params=None, task_id=None):
        task_id = task_id or self._task_id
        await self._send_message(
            {
                'msg': 'method',
                'method': name,
                'params': [params],
                'id': task_id
            }
        )
        return await self.method_request_handler(task_id)
    
    async def subscribe(self, name, params: list = []):
        task_id = generate_token(n=17)
        await self._send_message(
            {
                'msg': 'sub',
                'name': name,
                'params': params,
                'id': task_id
            }
        )
        return await self.sub_request_handler(
            self.METHOD_COLLECTION_TABLE.get(name) or name, task_id)
        
    @staticmethod
    def _to_json(data):
        return json.loads(json.loads(data[1:])[0])
    
    async def recv_message(self):
        r = await self.client.receive()
        try:
            return self._to_json(r.data)
        except:
            return await self.recv_message()
    
    async def recv_message_loop(self):
        while True:
            msg = await self.recv_message()
            
            if msg.get('msg') == 'error':
                raise AnyRunError(f'{msg["reason"]}, offendingMessage={msg["offendingMessage"]}')
            elif msg.get('error') is not None:
                raise AnyRunError(msg['error']['message'])
            else:
                return msg

    async def sub_request_handler(self, name, task_id):
        async def _handle():
            results = []
            while True:
                msg = await self.recv_message_loop()
                
                if msg.get('msg') == 'added':
                    if msg.get('collection') == name:
                        results.append(msg.get('fields'))
                elif msg.get('msg') == 'ready':
                    if msg.get('subs')[0] == task_id:
                        break
            return results
        return _handle    
    
    async def method_request_handler(self, task_id):
        async def _handle():
            while True:
                msg = await self.recv_message_loop()
                if msg.get('msg') == 'result':
                    if msg.get('id') == task_id:
                        return msg.get('result')
        return _handle    
    
    @staticmethod
    def create_params(
        is_public: bool = True,
        hash_: str = '',
        run_type: cst.RUN_TYPES.types = [],
        name: str = '',
        verdict: cst.VERDICTS.types = [],
        extensions: cst.EXTENSIONS.types = [],
        ip: str = '',
        domain: str = '',
        file_hash: str = '',
        mitre_id: str = '',
        suricata_sid: int = 0,
        significant: bool = False,
        tag: str = '',
        skip: int = 0) -> dict:
        
        run_type = [run_type] if isinstance(run_type, str) else run_type
        verdict = [verdict] if isinstance(verdict, str) else verdict
        extensions = [extensions] if isinstance(extensions, str) else extensions

        params = {
            'isPublic': is_public,
            'hash': hash_,
            'runtype': [cst.RUN_TYPES.data.get(_run_type.lower()) for _run_type in run_type],
            'name': name,
            'verdict': [cst.VERDICTS.data.get(v.lower()) for v in verdict],
            'ext': [cst.EXTENSIONS.data.get(ext.lower()) for ext in extensions],
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
    
    async def get_public_tasks(self, **kwargs):
        '''Get public tasks based on the given query parameters.'''

        params = self.create_params(**kwargs)
        
        resp_handler = await self.subscribe(
            'publicTasks', [params['skip']+50, params['skip'], params])
        
        return [collection.Task(msg) for msg in await resp_handler()]
    
    async def check_task_exists(self, task_uuid):
        resp_handler = await self.subscribe('taskexists', [task_uuid])
        return [msg['taskObjectId'] for msg in await resp_handler()]
    
    async def _get_single_task(self, task_obj_id):
        resp_handler = await self.subscribe('singleTask', [task_obj_id, False])
        return await resp_handler()
    
    async def get_single_task(self, task_uuid):
        task_obj_id = await self.check_task_exists(task_uuid)
        if not task_obj_id:
            raise AnyRunError(f'No task found. uuid={task_uuid}')
            
        task = await self._get_single_task(task_obj_id[0])
        if not task:
            raise AnyRunError(f'Failed to get task. uuid={task_uuid}')
            
        return task[0]
    
    async def search(self, **kwargs):
        params = self.create_params(**kwargs)
        resp_handler = await self.send_message('getTasks', params, generate_id())
        return await resp_handler()
