import json
from library_client import ThreatLibraryClient
from cti_client import CTIClient
import logging
from tqdm import tqdm


def process_hashes(rows,cti_client):
    for row in tqdm(rows):
        for hash_type in ['md5','sha1','sha256']:
            
            hash=row[hash_type]
            indicator=cti_client.fetch_indicator(hash)
            
            if indicator is not None:
                cti_client.label_indicator(indicator)
                note_params={
                    'file_id':row['file_id'],
                    'remote_file_id':row['remote_file_id'],
                    'action_id':row['action_id']
                }
                cti_client.note_indicator(indicator,note_params)
            else:
                logging.warning(f"Indicator for hash {hash} not found in CTI")



if __name__ == "__main__":
    with open ("config.json", "r") as config_file:
        config=json.load(config_file) 
    logging.basicConfig(filename=config['logging']['file'],level=config['logging']['level']) 
    cti_client=CTIClient(config['cti'])
    tl_client=ThreatLibraryClient(config['threat_library'])
    
    rows=tl_client.fetch_hashes()
    #mock, delete later
    # rows=json.load(open('/root/garbage/tl-rows.json','r'))
    process_hashes(rows,cti_client)
    
    
    
    