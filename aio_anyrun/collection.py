import typing as t
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
