"""
Data caching utilities for XSOAR ticket data to improve chart generation performance.
"""
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

import pytz

from my_config import get_config
from services.xsoar import TicketHandler

log = logging.getLogger(__name__)
config = get_config()
eastern = pytz.timezone('US/Eastern')


class DataCache:
    """Manages caching of XSOAR ticket data for chart generation."""
    
    def __init__(self):
        self.config = get_config()
        self.root_directory = Path(__file__).parent.parent.parent
        self.cache_base_dir = self.root_directory / "web" / "static" / "charts"
        self.ticket_handler = TicketHandler()
    
    def get_cache_file_path(self, date_str: str) -> Path:
        """Get the path for cached data file for a specific date."""
        return self.cache_base_dir / date_str / "cached_tickets_3months.json"
    
    def fetch_and_cache_3month_data(self, date_str: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch 3 months of ticket data from XSOAR and cache it locally.
        
        Args:
            date_str: Date string in MM-DD-YYYY format. If None, uses today.
            
        Returns:
            Dictionary containing the cached data with metadata.
        """
        if date_str is None:
            date_str = datetime.now().strftime('%m-%d-%Y')
        
        log.info(f"Fetching 3 months of ticket data for caching on {date_str}")
        
        # Create cache directory
        cache_file = self.get_cache_file_path(date_str)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Fetch 3 months of data
        query = f'type:{self.config.team_name} -owner:""'
        period = {"byFrom": "months", "fromValue": 3}
        
        try:
            # Call API directly to avoid any caching logic
            tickets = self.ticket_handler._fetch_from_api(
                query + f' -category:job -type:"{self.config.team_name} Ticket QA" -type:"{self.config.team_name} SNOW Whitelist Request"',
                period, 
                50000
            )
            
            # Create cache data structure
            cache_data = {
                "generated_at": datetime.now(eastern).isoformat(),
                "date": date_str,
                "query_info": {
                    "base_query": query,
                    "period": period,
                    "total_tickets": len(tickets)
                },
                "tickets": tickets
            }
            
            # Save to cache file
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            log.info(f"Cached {len(tickets)} tickets to {cache_file}")
            return cache_data
            
        except Exception as e:
            log.error(f"Failed to fetch and cache ticket data: {e}")
            return {"tickets": [], "error": str(e)}
    
    def get_cached_data(self, date_str: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get cached ticket data for the exact date requested only.
        
        Args:
            date_str: Date string in MM-DD-YYYY format. If None, uses today.
            
        Returns:
            Cached data dictionary or None if not found for exact date.
        """
        if date_str is None:
            date_str = datetime.now().strftime('%m-%d-%Y')
        
        # Only try the exact date requested - no fallback to older dates
        cache_file = self.get_cache_file_path(date_str)
        if cache_file.exists():
            return self._load_cache_file(cache_file)
        else:
            log.info(f"No cache file found for exact date {date_str}")
            return None
    
    def _load_cache_file(self, cache_file: Path) -> Optional[Dict[str, Any]]:
        """Load and validate a cache file."""
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            log.info(f"Loaded {len(data.get('tickets', []))} tickets from cache: {cache_file}")
            return data
        except Exception as e:
            log.error(f"Failed to load cached data from {cache_file}: {e}")
            return None
    
    def filter_cached_tickets(self, cached_data: Dict[str, Any], query: str, 
                            period: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Filter cached tickets based on query and period parameters.
        
        This is a simplified filtering - for complex queries, we fall back to API.
        
        Args:
            cached_data: The cached data dictionary
            query: The query string (simplified filtering)
            period: Period filter (if different from cached period)
            
        Returns:
            Filtered list of tickets
        """
        tickets = cached_data.get("tickets", [])
        
        # If no additional filtering needed beyond the base cache query, return all
        base_query = f'type:{self.config.team_name} -owner:""'
        if query == base_query and period is None:
            return tickets
        
        # For more complex filtering, we can implement specific logic here
        # For now, return all cached tickets and let the charts do their own filtering
        # This still saves the expensive API call
        return tickets


def fetch_daily_cache() -> None:
    """Daily job to fetch and cache 3 months of ticket data."""
    cache = DataCache()
    today_str = datetime.now().strftime('%m-%d-%Y')
    
    log.info("Starting daily data cache job")
    result = cache.fetch_and_cache_3month_data(today_str)
    
    if "error" not in result:
        log.info(f"Successfully cached {len(result.get('tickets', []))} tickets for {today_str}")
    else:
        log.error(f"Failed to cache data: {result['error']}")


if __name__ == "__main__":
    # Test the caching system
    cache = DataCache()
    cache.fetch_and_cache_3month_data()