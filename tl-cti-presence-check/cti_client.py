from pycti import OpenCTIApiClient

class CTIClient:
    def __init__(self, config):
        self.client = OpenCTIApiClient(config['url'], config['api_token'])
        self.label = self.client.label.create(
            value="threat-library-present",
            color="#00ff00",
            
        )
        self.note_template="### Threat Library Information\
            - File ID: {file_id}\
        "
        
    
    
    def fetch_indicator(self, hash):
        indicator=self.client.indicator.read(filters=[{'key':'value','values':[hash]}])
    
    
    def label_indicator(self,indicator):
        self.client.stix_domain_object.add_label(id=indicator['id'],label_id=self.label['id'])
        
    def note_indicator(self,indicator,note_params:dict):
        self.client.note.create(
            abstract="Threat Library Information",
            content=self.note_template.format(**note_params),
            objects=[indicator['id']]
                   
        )
    
        
    
        
