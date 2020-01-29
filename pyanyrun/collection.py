from pyanyrun import const as cst


class Task:
    def __init__(self, task_info):
        self._info = task_info
    
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
    def file_type(self):
        if self.run_type != 'url':
            return self.info['meta']['file']
    
    @property
    def mime_type(self):
        if self.run_type != 'url':
            return self.info['meta']['mime']
    
    @property
    def exif(self):
        if self.run_type != 'url':
            return self.info['meta']['exif']
    
    @property
    def ole(self):
        if self.run_type != 'url':
            return self.info['meta']['ole'] 