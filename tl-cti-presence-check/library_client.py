import psycopg2
import psycopg2.extras

class ThreatLibraryClient:
    def __init__(self, config):
        self.host = config['host']
        self.port = config['port']
        self.database = config['database']
        self.user = config['username']
        self.password = config['password']
        self.conn = psycopg2.connect(host=self.host, port=self.port, database=self.database, user=self.user, password=self.password)
        self.schema = config['schema']
        self.default_query=config['query']
    
    def fetch_hashes(self,query=None):
        cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        if query is None:
            cursor.execute(self.default_query)
        else:
            cursor.execute(query)
        results=cursor.fetchall()

        return results
        