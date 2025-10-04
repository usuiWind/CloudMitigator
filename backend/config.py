import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration"""
    AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'True') == 'True'
    
    # TTP mappings path - check if running in Docker container
    if os.path.exists('/app/data/ttp_mappings.json'):
        TTP_MAPPINGS_PATH = '/app/data/ttp_mappings.json'
    else:
        # Local development path
        TTP_MAPPINGS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'ttp_mappings.json')
