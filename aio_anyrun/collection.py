import typing as t
from datetime import datetime
from dataclasses import dataclass

from aio_anyrun import const as cst


class Task:
    def __init__(self, task_info: dict):
        self._info = task_info
    
    def __str__(self):
        return f'Task(run_type={self.run_type}, name={self.name}, verdict={self.verdict}, task_uuid={self.task_uuid}, object_uuid={self.object_uuid})'
    
    def __repr__(self):
        return self.__str__()
    
    @property
    def threat_level(self) -> int:
        return self._info['scores']['verdict']['threat_level']
    
    @property
    def verdict(self) -> str:
        level = self.threat_level
        for k, v in cst.VERDICTS.data.items():
            if v == level:
                return k
        return ''
    
    @property
    def tags(self) -> t.List[str]:
        return self._info['tags']
    
    @property
    def task_uuid(self) -> str:
        return self._info['uuid']
    
    @property
    def os_version(self) -> dict:
        return self._info['public']['environment']['OS']
    
    @property
    def run_type(self) -> str:
        return self._info['public']['objects']['runType']
    
    @property
    def main_object(self) -> dict:
        return self._info['public']['objects']['mainObject']
    
    @property
    def hashes(self) -> dict:
        return self.main_object['hashes']

    @property
    def md5(self) -> str:
        return self.hashes['md5']

    @property
    def sha1(self) -> str:
        return self.hashes['sha1']
    
    @property
    def sha256(self) -> str:
        return self.hashes['sha256']
    
    @property
    def object_uuid(self) -> str:
        return self.main_object['uuid']
    
    @property
    def names(self) -> dict:
        return self.main_object['names']
    
    @property
    def name(self) -> str:
        if self.run_type == 'file':
            return self.names['basename']
        else:
            return self.names['url']
    
    @property
    def info(self) -> dict:
        return self.main_object['info']
        
    @property
    def file_type(self) -> t.Optional[str]:
        if self.run_type != 'url':
            return self.info['meta']['file']
    
    @property
    def mime_type(self) -> t.Optional[str]:
        if self.run_type != 'url':
            return self.info['meta']['mime']
    
    @property
    def exif(self) -> t.Optional[dict]:
        if self.run_type != 'url':
            return self.info['meta']['exif']
    
    @property
    def ole(self) -> t.Optional[str]:
        if self.run_type != 'url':
            return self.info['meta']['ole'] 
    
    @property
    def is_downloadable(self) -> bool:
        return self.run_type != 'url'


StrOrInt = t.Union[int, str]

REPUTATION_TABLE: t.Dict[int, str] = {
    0: 'unknown',
    1: 'suspicious',
    2: 'malicious',
    3: 'whitelisted',
    4: 'unsafe'
}

@dataclass
class IoCObject:
    category: str = ''
    type: str = ''
    ioc: str = ''
    reputation: StrOrInt = ''
    name: str = ''
    
    def __post_init__(self):
        if self.reputation:
            self.reputation = REPUTATION_TABLE[t.cast(int, self.reputation)]


class IoC:
    ''' Class to represent IoC information.
    '''
    def __init__(self, ioc: dict):
        self.ioc = ioc
    
    def __str__(self) -> str:
        return f'IoC(main_object={self.main_objects}, dropped_files={self.dropped_files}, dns={self.dns}, connections={self.connections})'
    
    def __repr__(self) -> str:
        return self.__str__()
    
    @staticmethod
    def _parse(obj: t.Optional[dict]) -> t.List[IoCObject]:
        if obj is None:
            return [IoCObject()]
        return [IoCObject(**o) for o in obj]
    
    @property
    def main_objects(self) -> t.List[IoCObject]:
        return self._parse(self.ioc['Main object'])
    
    @property
    def dropped_files(self) -> t.List[IoCObject]:
        return self._parse(self.ioc.get('Dropped executable file'))
    
    @property
    def dns(self) -> t.List[IoCObject]:
        return self._parse(self.ioc.get('DNS requests'))
    
    @property
    def connections(self) -> t.List[IoCObject]:
        return self._parse(self.ioc.get('Connections'))


class MITRE_Attack:
    def __init__(self, mitre_data: dict):
        self.data = mitre_data
    
    @property
    def _external_references(self) -> t.List[dict]:
        return self.data['external_references']
    
    @property
    def mitre_url(self) -> t.Optional[str]:
        for ref in self._external_references:
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('url')
        return ''
    
    @property
    def technique(self) -> str:
        return self.data['technique']
    
    @property
    def name(self) -> str:
        return self.data['name']
    
    @property
    def mitre_detection(self) -> str:
        return self.data['x_mitre_detection']
    
    @property
    def platforms(self) -> t.List[str]:
        return self.data['x_mitre_platforms']
    
    @property
    def kill_chain_phases(self) -> t.List[dict]:
        return self.data['kill_chain_phases']
    
    @property
    def description(self) -> str:
        return self.data['description']
    
    @property
    def mitre_data_sources(self) -> t.List[str]:
        return self.data['x_mitre_data_sources']
    
    @property
    def created(self) -> datetime:
        return datetime.strptime(self.data['created'], '%Y-%m-%dT%H:%M:%S.%f%z')