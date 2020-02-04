import aiohttp
import json
import hashlib
import time
import string
import random
import typing as t
from pathlib import Path

try:
    from contextlib import asynccontextmanager
except ImportError:
    from async_generator import asynccontextmanager

from aio_anyrun import collection
from aio_anyrun import const as cst

# this will be used on downloading file
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36'


def generate_token(n: int = 8) -> str:
    letters = string.ascii_lowercase + '1234567890'
    return ''.join(random.choice(letters) for _ in range(n))

def generate_id() -> str:
    return str(random.randint(100, 999))

def generate_random_int_str(n: int = 10) -> str:
    letters = '1234567890'
    return ''.join(random.choice(letters) for _ in range(n))

def generate_google_analytics_id() -> str:
    return f'GA1.2.{generate_random_int_str()}.{int(time.time())}'

def generate_random_cookies_with_token(token: str) -> dict:
    return {
        '__cfduid': hashlib.sha256(generate_random_int_str().encode('utf-8')).hexdigest(),
        '_ga': generate_google_analytics_id(),
        '_gid': generate_google_analytics_id(),
        'tokenLogin': token}

async def download_file(
    task_uuid: str,
    object_uuid: str,
    token: str,
    dest: str = '.',
    raise_for_status: bool = True,
    chunk_size: int = 1024
) -> Path:
    ''' Download file from ANY.RUN.
    Args:
        task_uuid: UUID of task
        object_uuid: UUID of object in task
        token: login token, this can be retrieve when you login
        raise_for_status: if True, raise exception when status is not 200
        chunk_size: chunk size to read for each time
    '''
    
    url = f'https://content.any.run/tasks/{task_uuid}/download/files/{object_uuid}'
    headers = {
        'Referer': f'https://app.any.run/tasks/{task_uuid}/',
        'User-Agent': DEFAULT_USER_AGENT
    }

    cookies = generate_random_cookies_with_token(token)

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, cookies=cookies, raise_for_status=raise_for_status) as resp:
            save_path = Path(dest, resp.content_disposition.filename)
            with save_path.open('wb') as fd:
                async for chunk in resp.content.iter_chunked(chunk_size):
                    fd.write(chunk)
                return save_path

async def _login_request_handler(
    client: 'AnyRunClient',
    name: str,
    task_id: str
) -> cst.HANDLER_FUNC:
    ''' Customized response handler for login request.
    '''
    async def _handle() -> t.Optional[dict]:
        while True:
            msg = await client.recv_message_loop()

            if msg.get('msg') == 'added':
                if msg.get('collection') == name:
                    return msg.get('fields')
    return _handle    

async def _sub_request_handler(
    client: 'AnyRunClient',
    name: str,
    task_id: str
) -> cst.HANDLER_FUNC:
    ''' Default response handler for sub request.
    '''
    async def _handle():
        results = []
        while True:
            msg = await client.recv_message_loop()
            
            if msg.get('msg') == 'added':
                if msg.get('collection') == name:
                    results.append(msg.get('fields'))
            elif msg.get('msg') == 'ready':
                if msg.get('subs')[0] == task_id:
                    break
        return results
    return _handle    

async def _method_request_handler(
    client: 'AnyRunClient',
    _: str,
    task_id: str
) -> cst.HANDLER_FUNC:
    ''' Default response handler for method request.
    '''
    async def _handle():
        while True:
            msg = await client.recv_message_loop()
            if msg.get('msg') == 'result':
                if msg.get('id') == task_id:
                    return msg.get('result')
    return _handle 

class AnyRunError(Exception):
    pass


class AnyRunClient:
    ''' Asynchronous client for AnyRun.
    Usage:
        1. connect with contextmanager
        ... from aio_anyrun.client import AnyRunClient
        ... async with AnyRunClient.connect() as client:
        ...     tasks = await client.get_public_tasks()

        2. connect by your self (close connection by yourself)
        ... from aio_anyrun.client import AnyRunClient
        ... client = AnyRunClient()
        ... await client.init_connection_with_default_client()
        ... tasks = await client.get_public_tasks()
        ... await client.close()
    '''

    # conversion table of method name and collection name
    METHOD_COLLECTION_TABLE = {
        'singleTask': 'tasks',
        'publicTasks': 'tasks',
        'login': 'users',
        'taskexists': 'taskExists'
        
    }

    def __init__(self):
        self.session = aiohttp.ClientSession()
        self.client = None
        self.login_token = None
        self._current_token_id = 1
    
    async def _init_client(
        self,
        user_agent: str = '',
        autoclose: bool = True,
        timeout: int = 30
    ):
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
        ''' Initialize client and connection.
        Need call this method before send messages if you init AnyClient by yourself.
        '''
        await self._init_client()
        await self._init_connection()
    
    async def close(self):
        await self.client.close()
        await self.session.close()

    @staticmethod
    @asynccontextmanager
    async def connect(
        user_agent: str = '',
        autoclose: bool = True,
        timeout: int = 30
    ) -> t.AsyncIterator['AnyRunClient']:
        ''' Create AnyRun client with contextmanager.
        Args:
            user_agent: User-Agent for client, default is no string
            autoclose: to close connection automatically or not
            timeout: connection timeout as second, default is 30 second.
        '''
        try:
            anyrun = AnyRunClient()
            await anyrun._init_client(user_agent, autoclose, timeout)
            await anyrun._init_connection()
            yield anyrun
            
        finally:
            await anyrun.close()

    @property
    def _task_id(self) -> str:
        c_token = self._current_token_id
        self._current_token_id += 1
        return str(c_token)
    
    async def _send_message(self, msg: dict):
        await self.client.send_json([json.dumps(msg)])
        
    async def send_message(
        self,
        name: str,
        params: t.Optional[t.Union[dict, list]] = None,
        task_id: t.Optional[str] = None,
        handler: t.Callable[['AnyRunClient', str, str], cst.HANDLER_FUNC] = _method_request_handler
    ) -> cst.HANDLER_FUNC:
        ''' Send method request message.
        Args:
            name: method name for request
            params: request parameters
            task_id: usually use incrementing task id, 
                but just in case, you can pass any id as well.
            handler: response handler for method request.
        '''
        task_id = task_id or self._task_id
        params = [params] if isinstance(params, dict) else params
        await self._send_message(
            {
                'msg': 'method',
                'method': name,
                'params': [params],
                'id': task_id
            }
        )
        return await handler(self, self.METHOD_COLLECTION_TABLE.get(name) or name, task_id)
    
    async def subscribe(
        self, 
        name: str, 
        params: t.Optional[list] = None,
        handler: t.Callable[['AnyRunClient', str, str], cst.HANDLER_FUNC] =_sub_request_handler
    ) -> cst.HANDLER_FUNC:
        ''' Send subscription request message.
        Args:
            name: subscription name for request
            params: request parameters
            handler: response handler for sub request.
        '''
        task_id = generate_token(n=17)
        await self._send_message(
            {
                'msg': 'sub',
                'name': name,
                'params': params or [],
                'id': task_id
            }
        )
        return await handler(
            self, self.METHOD_COLLECTION_TABLE.get(name) or name, task_id)
        
    @staticmethod
    def _to_json(data: str) -> dict:
        ''' parse response from ANY.RUN. it always be like '"a[{...}]"'.
        so we should remove first meaningless char and parse as json.
        '''
        return json.loads(json.loads(data[1:])[0])
    
    async def recv_message(self) -> dict:
        r = await self.client.receive()
        try:
            return self._to_json(r.data)
        except:
            return await self.recv_message()
    
    async def recv_message_loop(self) -> dict:
        ''' do loop and return message when any valid response is retrieved. 
        if any error message is returned, raise exception.
        '''
        while True:
            msg = await self.recv_message()
            
            if msg.get('msg') == 'error':
                raise AnyRunError(f'{msg["reason"]}, offendingMessage={msg["offendingMessage"]}')
            elif msg.get('error') is not None:
                raise AnyRunError(msg['error']['message'])
            else:
                return msg   
    
    @staticmethod
    def _create_params(
        is_public: bool = True,
        hash_: str = '',
        run_type: t.Optional[cst.RUN_TYPES.types] = None,
        name: str = '',
        verdict: t.Optional[cst.VERDICTS.types] = None,
        extensions: t.Optional[cst.EXTENSIONS.types] = None,
        ip: str = '',
        domain: str = '',
        file_hash: str = '',
        mitre_id: str = '',
        suricata_sid: int = 0,
        significant: bool = False,
        tag: str = '',
        skip: int = 0
    ) -> dict:
        ''' Create parameters for search or get tasks.
        Args:
            is_public: always True.
            hash_: file hash for task to search. this hash is ONLY for submitted object by user.
                it means that this hash is NOT for files dropped in sandbox during running.
                for hash for dropped files, use `file_hash` param.
            run_type: object type of task. 'file' or/and 'url' is acceptable.
                if you just want to search single type, pass as `str` (i.e. `run_type='file'`).
                if you want to search both, pass both as list (i.e. `run_type=['file', 'url']`).
            name: filename or URL to search.
            verdict: 'malicious', 'normal' and/or 'no-threats' are acceptable.
            extensions: following file types are acceptable.
                'exe', 'dll', 'java', 'html', 'flash', 'pdf', 'office', 'script', 'email'
            ip: ip address to search. this param can search IPs found during analyzing in sandbox.
            domain: domain name to search. this param can search domains found during analyzing in sandbox.
            file_hash: file hash to search. this param can search hashes found during analyzing in sandbox.
            mitre_id: MITRE ATT&CK ID to search. only one ID is acceptable.
            tag: tag name to search. only one tag is acceptable.
            skip: skip number of task to search. this is usd for paging.
                if you want to search past 50~100, pass like `skip=50`.
        '''
        
        run_type = [run_type] if isinstance(run_type, str) else run_type or []
        verdict = [verdict] if isinstance(verdict, str) else verdict or []
        extensions = [extensions] if isinstance(extensions, str) else extensions or []

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
    
    async def get_public_tasks(self, **kwargs) -> t.List[collection.Task]:
        '''Get public tasks based on the given query parameters.
        currently only latest 50 task will be retrieved. for more details 
        of available parameters, see `_create_params`.
        '''
        params = self._create_params(**kwargs)
        
        resp_handler = await self.subscribe(
            'publicTasks', [params['skip']+50, params['skip'], params])
        
        return [collection.Task(msg) for msg in await resp_handler()]
    
    async def check_task_exists(self, task_uuid: str) -> t.List[dict]:
        resp_handler = await self.subscribe('taskexists', [task_uuid])
        return [msg['taskObjectId'] for msg in await resp_handler()]
    
    async def _get_single_task(self, task_obj_id: dict):
        resp_handler = await self.subscribe('singleTask', [task_obj_id, False])
        return await resp_handler()
    
    async def get_single_task(self, task_uuid: str) -> collection.Task:
        ''' Search task based on given UUID.
        you can get UUID by using `get_public_tasks` or just copy <UUID> part of 
        URL of ANY.RUN on browser ('https://app.any.run/tasks/<UUID>/').
        '''
        task_obj_id = await self.check_task_exists(task_uuid)
        if not task_obj_id:
            raise AnyRunError(f'No task found. uuid={task_uuid}')
            
        task = await self._get_single_task(task_obj_id[0])
        if not task:
            raise AnyRunError(f'Failed to get task. uuid={task_uuid}')
            
        return collection.Task(task[0])
    
    async def search(self, **kwargs) -> t.List[collection.Task]:
        ''' Search based on given params. currently only latest 50 task will be retrieved.
        for more details of available parameters, see `_create_params`.
        '''
        params = self._create_params(**kwargs)
        resp_handler = await self.send_message('getTasks', params, generate_id())
        tasks = await resp_handler()
        return [collection.Task(res) for res in tasks['res']]

    async def download_file(self, task: collection.Task, dest: str = '.') -> Path:
        ''' Download file based on given task. saved filename is based on filename on AnyRun.

        Args:
            task: Task object which can be retrieved by 
                `get_single_task`, `get_public_tasks` or `search`.
            dest: destination folder to save file.
        '''
        if not self.login_token:
            raise AnyRunError('Token not found. Need to login before downloading file.')
            
        if not task.is_downloadable:
            raise AnyRunError(
                f'Task(guid={task.task_uuid}) is "{task.run_type}" type. not downloadable.')
        
        return await download_file(
            task.task_uuid, task.object_uuid, self.login_token, dest)
    
    async def logout(self):
        if self.login_token is not None:
            await self.send_message('logout')
            self.login_token = None
    
    async def login(self, email: str, password: str) -> bool:
        ''' Login to ANY.RUN. make sure you have correct account info.
        '''
        if not self.login_token:
            resp_handler = await self.send_message(
                'login',
                {
                    'user': {'email': email},
                    'password': {
                        'digest': hashlib.sha256(password.encode('utf-8')).hexdigest(),
                        'algorithm': 'sha-256'
                    }
                },
                handler=_login_request_handler
            )
            info = await resp_handler()
            
            # get latest token
            self.login_token = info['services']['resume']['loginTokens'][-1]['hashedToken']

        return self.login_token is not None
    
    async def get_ioc(self, task_uuid: str) -> collection.IoC:
        ''' Get IoC information of given UUID.
        '''
        resp_handler = await self.send_message(
            'getIOC',
            params=['any.run', task_uuid]
        )
        ioc = await resp_handler()
        return collection.IoC(ioc)

    async def get_process_graph(self, task_uuid: str) -> str:
        ''' Get process sequence graph as SVG.
        '''
        resp_handler = await self.send_message(
            'renderGraph',
            params=[task_uuid, 'any.run']
        )
        graph = await resp_handler()
        return graph
    