"""
Specialized Hunting Modules Package
"""

from hunting.specialized.xss_hunter import XSSHunter, DOMXSSHunter, BlindXSSHunter
from hunting.specialized.sqli_hunter import SQLiHunter
from hunting.specialized.ssrf_hunter import SSRFHunter, BlindSSRFHunter
from hunting.specialized.rce_hunter import RCEHunter, FileUploadRCEHunter
from hunting.specialized.auth_hunter import AuthHunter
from hunting.specialized.logic_hunter import LogicHunter
from hunting.specialized.api_hunter import APIHunter
from hunting.specialized.mobile_hunter import MobileHunter, MobileAPIHunter
from hunting.specialized.cloud_hunter import CloudHunter, ServerlessHunter
from hunting.specialized.supply_chain_hunter import SupplyChainHunter

__all__ = [
    'XSSHunter',
    'DOMXSSHunter',
    'BlindXSSHunter',
    'SQLiHunter',
    'SSRFHunter',
    'BlindSSRFHunter',
    'RCEHunter',
    'FileUploadRCEHunter',
    'AuthHunter',
    'LogicHunter',
    'APIHunter',
    'MobileHunter',
    'MobileAPIHunter',
    'CloudHunter',
    'ServerlessHunter',
    'SupplyChainHunter',
]