import pytest
from pathlib import Path
from src.epp import tanium_hosts_without_ring_tag

def test_get_region_from_country():
    # Test known country
    assert tanium_hosts_without_ring_tag._get_region_from_country('United States') == 'US'
    # Test unknown country
    assert tanium_hosts_without_ring_tag._get_region_from_country('Atlantis') == ''

# You can add more tests for other core logic as needed

