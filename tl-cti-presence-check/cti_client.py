from pycti import OpenCTIApiClient,Note
from datetime import datetime


class CTIClient:
    def __init__(self, config):
        self.client = OpenCTIApiClient(config['url'], config['api_token'])
        self.label = self.client.label.create(
            value="threat-library-present",
            color="#00ff00",
            
        )
        self.note_template="### Threat Library Information\n\
            * File IDs: {file_id}\n\
            * Remote File IDs: {remote_file_id}\n\
            * Action IDs: {action_id}\n\
        "
        #set default date to be year 0
        self.default_date=datetime(1111,1,1,0,0,0,0).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z"
    
    
    def fetch_indicator(self, hash):
        indicator=self.client.indicator.read(filters=[{'key':'name','values':[hash]}])
        return indicator
    
    
    def label_indicator(self,indicator):
        self.client.stix_domain_object.add_label(id=indicator['id'],label_id=self.label['id'])
        
    def note_indicator(self,indicator,note_params:dict):
        content=self.note_template.format(**note_params)
        self.client.note.create(
            abstract="Threat Library Information",
            content=content,
            objects=[indicator['id']],
            created=self.default_date               
        )
        Note.generate_id(self.default_date,indicator['id'])
        
    
        
    
        
