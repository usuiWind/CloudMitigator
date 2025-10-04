import json
import logging
import os
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class TTPMapper:
    """Maps MITRE ATT&CK TTPs to AWS mitigations"""
    
    def __init__(self, mappings_path: str):
        self.mappings_path = mappings_path
        self.mappings = self._load_mappings()
    
    def _load_mappings(self) -> Dict:
        """Load TTP mappings from JSON file"""
        try:
            logger.info(f"Attempting to load TTP mappings from: {self.mappings_path}")
            with open(self.mappings_path, 'r') as f:
                mappings = json.load(f)
            logger.info(f"Successfully loaded {len(mappings)} TTP mappings")
            return mappings
        except FileNotFoundError:
            logger.error(f"Mappings file not found: {self.mappings_path}")
            logger.error(f"Current working directory: {os.getcwd()}")
            logger.error(f"File exists check: {os.path.exists(self.mappings_path)}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in mappings file: {e}")
            return {}
    
    def get_all_ttps(self) -> Dict:
        """Get all TTP mappings"""
        return self.mappings
    
    def get_ttp(self, ttp_id: str) -> Optional[Dict]:
        """Get specific TTP mapping by ID"""
        return self.mappings.get(ttp_id.upper())
    
    def search_ttps(self, query: str) -> Dict:
        """Search TTPs by ID, name, or description"""
        query = query.lower()
        results = {}
        
        for ttp_id, ttp_data in self.mappings.items():
            if (query in ttp_id.lower() or
                query in ttp_data.get('name', '').lower() or
                query in ttp_data.get('description', '').lower()):
                results[ttp_id] = ttp_data
        
        return results
    
    def get_by_service(self, aws_service: str) -> Dict:
        """Get all TTPs for a specific AWS service"""
        return {
            ttp_id: ttp_data
            for ttp_id, ttp_data in self.mappings.items()
            if ttp_data.get('aws_service') == aws_service
        }
