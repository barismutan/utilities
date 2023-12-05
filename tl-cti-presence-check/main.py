import json
from library_client import ThreatLibraryClient
from cti_client import CTIClient
import logging


def process_hashes(hashes,cti_client):
    for hash in hashes:
        indicator=cti_client.fetch_indicator(hash)
        if indicator is None:
            logging.info("Indicator for hash {} not found in CTI".format(hash))
        else:
            logging.info("Indicator for hash {} found".format(hash))
            cti_client.label_indicator(indicator)
            cti_client.note_indicator(indicator,{'file_id':indicator['id']})



if __name__ == "__main__":  
    with open ("config.json", "r") as config_file:
        config=json.load(config_file) 
    logging.basicConfig(filename=config['logging']['file'],level=config['logging']['level']) 
    cti_client=CTIClient(config['cti'])
    tl_client=ThreatLibraryClient(config['threat_library'])
    hashes=tl_client.fetch_hashes()
    flattened_hashes=[item for sublist in hashes for item in sublist]
    logging.info("Fetched {} hashes from threat library".format(len(flattened_hashes)))
    
    
    
    