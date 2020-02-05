import json
import typing as t
from datetime import datetime

from aio_anyrun import const as cst


class BaseCollection:
    def __init__(self, raw_data: dict):
        self.raw_data = raw_data
        self._ignores = ['items', 'json', 'raw_data', 'keys', 'values']
        self.properties = [prop for prop in dir(self) if not prop.startswith('_') and prop not in self._ignores]
    
    def json(self):
        return json.dumps(self.raw_data, indent=4)
    
    def __str__(self):
        return f'{self.__name__}({ ", ".join([f"{k}={v}" for k, v in self.items()]) })'

    def __repr__(self):
        return self.__str__()

    def __getitem__(self, key):
        return self.raw_data.get(key)
    
    def items(self):
        for prop in self.properties:
            yield prop, getattr(self, prop)


class Task(BaseCollection):    
    @property
    def threat_level(self) -> int:
        return self.raw_data['scores']['verdict']['threat_level']
    
    @property
    def verdict(self) -> str:
        level = self.threat_level
        for k, v in cst.VERDICTS.data.items():
            if v == level:
                return k
        return ''
    
    @property
    def tags(self) -> t.List[str]:
        return self.raw_data['tags']
    
    @property
    def task_uuid(self) -> str:
        return self.raw_data['uuid']
    
    @property
    def os_version(self) -> dict:
        return self.raw_data['public']['environment']['OS']
    
    @property
    def run_type(self) -> str:
        return self.raw_data['public']['objects']['runType']
    
    @property
    def main_object(self) -> dict:
        return self.raw_data['public']['objects']['mainObject']
    
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

class IoCObject(BaseCollection):
    @property
    def category(self):
        return self.raw_data.get('category')
    
    @property
    def types(self):
        return self.raw_data.get('type')
    
    @property
    def ioc(self):
        return self.raw_data.get('ioc')
    
    @property
    def reputation(self):
        return REPUTATION_TABLE[self.raw_data['reputation']]
    
    @property
    def name(self):
        return self.raw_data.get('name')


class IoC(BaseCollection):
    ''' Class to represent IoC information.
    '''        
    @staticmethod
    def _parse(obj: t.Optional[dict]) -> t.List[IoCObject]:
        if obj is None:
            return []
        return [IoCObject(o) for o in obj]
    
    @property
    def main_objects(self) -> t.List[IoCObject]:
        return self._parse(self.raw_data['Main object'])
    
    @property
    def dropped_files(self) -> t.List[IoCObject]:
        return self._parse(self.raw_data.get('Dropped executable file'))
    
    @property
    def dns(self) -> t.List[IoCObject]:
        return self._parse(self.raw_data.get('DNS requests'))
    
    @property
    def connections(self) -> t.List[IoCObject]:
        return self._parse(self.raw_data.get('Connections'))


class MITRE_Attack(BaseCollection):    
    @property
    def _external_references(self) -> t.Optional[t.List[dict]]:
        return self.raw_data.get('external_references')
    
    @property
    def mitre_url(self) -> t.Optional[str]:
        for ref in self._external_references:
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('url')
        return ''
    
    @property
    def technique(self) -> t.Optional[str]:
        return self.raw_data.get('technique')
    
    @property
    def name(self) -> t.Optional[str]:
        return self.raw_data.get('name')
    
    @property
    def mitre_detection(self) -> t.Optional[str]:
        return self.raw_data.get('x_mitre_detection')
    
    @property
    def platforms(self) -> t.Optional[t.List[str]]:
        return self.raw_data.get('x_mitre_platforms')
    
    @property
    def kill_chain_phases(self) -> t.Optional[t.List[dict]]:
        return self.raw_data.get('kill_chain_phases')
    
    @property
    def description(self) -> t.Optional[str]:
        return self.raw_data.get('description')
    
    @property
    def mitre_data_sources(self) -> t.Optional[t.List[str]]:
        return self.raw_data.get('x_mitre_data_sources')
    
    @property
    def created(self) -> t.Optional[datetime]:
        if self.raw_data.get('created'):
            return datetime.strptime(self.raw_data['created'], '%Y-%m-%dT%H:%M:%S.%f%z')
