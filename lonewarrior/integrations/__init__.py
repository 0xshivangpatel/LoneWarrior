"""
LoneWarrior Integrations Module

Optional integrations with external security tools:
- Wazuh (SIEM/EDR)
- ModSecurity (WAF)
- Suricata (IDS/IPS)

These integrations read signals from external tools to boost confidence scores,
but LoneWarrior NEVER depends on them - it works perfectly standalone.
"""

from .wazuh import WazuhAdapter
from .modsecurity import ModSecurityAdapter
from .suricata import SuricataAdapter

__all__ = ['WazuhAdapter', 'ModSecurityAdapter', 'SuricataAdapter']
