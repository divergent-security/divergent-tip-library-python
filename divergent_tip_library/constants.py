discovery_mechanisms = {
  "SCAN": "The information was discovered by actively scanning the network or host",
  "MANUAL": "The information was manually entered by a user",
  "INTERACTIVE": "The information was discovered through interaction with the application",
  "QUERY": "The information was discovered through a query to a public information repository such as DNS or WHOIS",
  "SEARCH": "The information was discovered through a search provider such as Google or Bing",
  "SOCIAL": "The information was discovered on a social media site such as Facebook or Linkedin",
  "BREACH": "The information was discovered in a public breach data disclosure",
  "REPO": "The information was discovered by searching source code repositories such as Github",
  "PASTE": "The information was discovered by searching paste sites such as Pastebin"
}

event_types = {
  "NEW": None,
  "CHANGE": None,
  "TAG": None,
  "ACCEPT": None,
  "CONSTANT": None,
  "HOURLY": None,
  "DAILY": None,
  "WEEKLY": None,
  "MONTHLY": None
}

conditional_operations = {
  "EQUAL": 3,
  "LESS": 3,
  "MORE": 3,
  "MATCHES": 3,
  "LIST-MATCH": 3,
  "LIST-NO-MATCH": 3,
  "EXISTS": 2,
  "CHANGED": 2,
  "TRUE": 2,
  "FALSE": 2,
}

processor_usage_strings = {
  0: "TRIVIAL",
  1: "MINOR",
  2: "MEDIUM",
  3: "MAJOR",
  4: "INTENSE",
  5: "MELTDOWN"
}

supported_services = {
  "UNSUPPORTED": None,
  "HTTP": None,
  "SMB": None,
  "FTP": None,
  "SNMP": None,
  "SMTP": None,
  "LDAP": None,
  "SIP": None,
  "XMPP": None,
  "SQL": None,
}

protocols = [ "IP", "TCP", "UDP" ]

priority_strings = {
  0: "Informational",
  1: "Triage Needed",
  2: "Interesting",
  3: "Important",
  4: "Vulnerability"
}

loggable_events = [
  "NETWORK-NEW",
  "NETWORK-CHANGE",
  "DOMAIN-NEW",
  "DOMAIN-CHANGE"
]

job_input_classes = {
  "Netblock": {
    "type": basestring,
    "project.label": basestring,
    "label": basestring,
    "notes": basestring,
    "hidden": bool,
    "accepted": bool,
    "priority": int,
    "closed": bool,
    "discovery": basestring,
    "tags": (list, basestring),
    "ip.version": int,
    "ip.public": bool,
    "ip.cidr": basestring,
    "registered.net.name": basestring,
    "registered.net.handle": basestring,
    "registered.asn": basestring,
    "registered.asn.country": basestring,
    "registered.asn.description": basestring,
    "registered.asn.registry": basestring,
    "registered.asn.cidr": basestring,
    "registered.org.name": basestring,
    "registered.org.ID": basestring,
    "registered.org.description": basestring,
    "registered.org.address": basestring,
    "registered.org.city": basestring,
    "registered.org.state": basestring,
    "registered.org.zip": basestring,
    "registered.created": basestring,
    "registered.updated": basestring,
    "services.tcp": (list, int),
    "services.udp": (list, int)
  },
  "Domain": {
    "type": basestring,
    "project.label": basestring,
    "label": basestring,
    "notes": basestring,
    "hidden": bool,
    "accepted": bool,
    "priority": int,
    "closed": bool,
    "discovery": basestring,
    "tags": (list, basestring),
    "name": basestring,
    "id": basestring,
    "nameservers": (list, basestring),
    "registration.created": basestring,
    "registration.expires": basestring,
    "registration.updated": basestring,
    "registration.registrar": basestring,
    "registration.status": basestring,
    "whois.server": basestring
  },
  "Host": {
    "type": basestring,
    "project.label": basestring,
    "label": basestring,
    "notes": basestring,
    "hidden": bool,
    "accepted": bool,
    "priority": int,
    "closed": bool,
    "discovery": basestring,
    "tags": (list, basestring),
    "network.ip.version": int,
    "network.ip.public": bool,
    "network.ip.cidr": basestring,
    "network.ports.tcp": (list, int),
    "network.ports.udp": (list, int),
    "address": basestring,
    "mac": basestring,
    "icmp.enabled": bool,
    "fingerprint.type": basestring,
    "up": bool,
    "hostnames": (list, basestring),
    "services.up": (list, basestring),
    "services.tracking": (list, basestring)
  },
  "Service": {
    "type": basestring,
    "project.label": basestring,
    "label": basestring,
    "notes": basestring,
    "hidden": bool,
    "accepted": bool,
    "priority": int,
    "closed": bool,
    "discovery": basestring,
    "tags": (list, basestring),
    "network.ip.version": int,
    "network.ip.public": bool,
    "network.ip.cidr": basestring,
    "host.address": basestring,
    "host.icmp.enabled": bool,
    "host.fingerprint.type": basestring,
    "host.up": bool,
    "host.hostnames": (list, basestring),
    "protocol": basestring,
    "port": int,
    "fingerprint.version": basestring,
    "fingerprint.type": basestring,
    "ssl.enabled": bool,
    "class": basestring,
    "up": bool
  },
  "Hostname": {
    "type": basestring,
    "project.label": basestring,
    "label": basestring,
    "notes": basestring,
    "hidden": bool,
    "accepted": bool,
    "priority": int,
    "closed": bool,
    "discovery": basestring,
    "tags": (list, basestring),
    "network.ip.version": int,
    "network.ip.public": bool,
    "network.ip.cidr": basestring,
    "hosts": (list, basestring),
    "host.up": bool,
    "domain.name": basestring,
    "hostname": basestring,
    "resolvable": bool
  },
  "URL": {
    "type": basestring,
    "project.label": basestring,
    "label": basestring,
    "notes": basestring,
    "hidden": bool,
    "accepted": bool,
    "priority": int,
    "closed": bool,
    "discovery": basestring,
    "tags": (list, basestring),
    "network.ip.version": int,
    "network.ip.public": bool,
    "network.ip.cidr": basestring,
    "host.address": basestring,
    "host.icmp.enabled": bool,
    "host.fingerprint.type": basestring,
    "host.up": bool,
    "service.protocol": basestring,
    "service.port": int,
    "service.fingerprint.version": basestring,
    "service.fingerprint.type": basestring,
    "service.ssl.enabled": bool,
    "service.class": basestring,
    "service.up": bool,
    "url": basestring,
    "path": basestring,
    "scripts": (list, basestring),
    "headers": (list, basestring)
  },
  "Custom": {
    "type": basestring,
    "project.label": basestring,
    "label": basestring,
    "notes": basestring,
    "hidden": bool,
    "accepted": bool,
    "priority": int,
    "closed": bool,
    "discovery": basestring,
    "tags": (list, basestring),
    "name": basestring,
    "keys": (list, basestring),
    "values": (list, basestring)
  }
}

job_output_classes = {
  "Netblock": {
    "tags": (list, (basestring, 'Name')),
    "ip.version": (int, [4,6]),
    "ip.public": (bool, [True, False]),
    "ip.cidr": (basestring, 'CIDR'),
    "registered.net.name": (basestring, 'Name'),
    "registered.net.handle": (basestring, 'Name'),
    "registered.asn": (basestring, 'Name'),
    "registered.asn.country": (basestring, 'Name'),
    "registered.asn.description": (basestring, 'FreeForm'),
    "registered.asn.registry": (basestring, 'Name'),
    "registered.asn.cidr": (basestring, 'CIDR'),
    "registered.org.name": (basestring, 'FreeForm'),
    "registered.org.id": (basestring, 'Name'),
    "registered.created": (basestring, 'DateTime'),
    "registered.updated": (basestring, 'DateTime'),
    "registered.org.description": (basestring, 'FreeForm'),
    "registered.org.address": (basestring, 'FreeForm'),
    "registered.org.city": (basestring, 'FreeForm'),
    "registered.org.country": (basestring, 'Name'),
    "registered.org.state": (basestring, 'Name'),
    "registered.org.zip": (basestring, 'Name')
  },
  "Domain": {
    "tags": (list, (basestring, 'Name')),
    "name": (basestring, 'ResolvableName'),
    "id": (basestring, 'Name'),
    "nameservers": (list, (basestring, 'ResolvableName')),
    "registration.created": (basestring, 'DateTime'),
    "registration.expires": (basestring, 'DateTime'),
    "registration.updated": (basestring, 'DateTime'),
    "registration.registrar": (basestring, 'FreeForm'),
    "registration.status": (basestring, 'FreeForm'),
    "whois.server": (basestring, 'ResolvableName'),
    "whois.raw": (basestring, 'FreeForm')
  },
  "Host": {
    "tags": (list, (basestring, 'Name')),
    "network": (basestring, 'Netblock'),
    "address": (basestring, 'IPAddress'),
    "mac": (basestring, 'MACAddress'),
    "icmp.enabled": (bool, [True, False]),
    "fingerprint.type": (basestring, 'FreeForm'),
    "up": (bool, [True, False]),
    "hostnames": (list, (basestring, 'ResolvableName'))
  },
  "Service": {
    "tags": (list, (basestring, 'Name')),
    "host": (basestring, 'Host'),
    "host.address": (basestring, 'IPAddress'),
    "protocol": (basestring, protocols),
    "port": (int, range(0, 65535)),
    "fingerprint.version": (basestring, 'FreeForm'),
    "fingerprint.type": (basestring, 'FreeForm'),
    "ssl.enabled": (bool, [True, False]),
    "class": (basestring, supported_services.keys()),
    "up": (bool, [True, False])
  },
  "Certificate": {
    "tags": (list, (basestring, 'Name')),
    "service": (basestring, 'Service'),
    "serialnumber": (basestring, 'FreeForm'),
    "signature.algorithm": (basestring, 'FreeForm'),
    "hash.algorithm": (basestring, 'FreeForm'),
    "issuer": (basestring, 'FreeForm'),
    "created": (basestring, 'DateTime'),
    "expires": (basestring, 'DateTime'),
    "publickey": (basestring, 'FreeForm'),
    "valid": (bool, [True, False]),
    "hostnames": (list, (basestring, 'Hostname')),
  },
  "Hostname": {
    "tags": (list, (basestring, 'Name')),
    "domain": (basestring, 'Domain'),
    "hosts": (list, (basestring, 'Host')),
    "addresses": (list, (basestring, 'IPAddress')),
    "hostname": (basestring, 'ResolvableName'),
    "resolvable": (bool, [True, False])
  },
  "URL": {
    "tags": (list, (basestring, 'Name')),
    "hostname": (basestring, 'Hostname'),
    "service": (basestring, 'Service'),
    "url": (basestring, 'URLPath'),
    "scripts": (list, (basestring, 'URLPath')),
    "headers": (list, (basestring, 'FreeForm'))
  },
  "Cookie": {
    "tags": (list, (basestring, 'Name')),
    "url": (basestring, 'URL'),
    "path": (basestring, 'FreeForm'),
    "domain": (basestring, 'FreeForm'),
    "name": (basestring, 'Name'),
    "value": (basestring, 'FreeForm'),
    "secure": (bool, [True, False]),
    "httponly": (bool, [True, False]),
    "samesite": (basestring, ['strict', 'lax']),
    "maxage": (basestring, 'FreeForm')
  },
  "Parameter": {
    "tags": (list, (basestring, 'Name')),
    "url": (basestring, 'URL'),
    "name": (basestring, 'Name'),
    "format": (basestring, ['GET', 'POST']),
    "values": (list, (basestring, 'FreeForm'))
  },
  "Custom": {
    "tags": (list, (basestring, 'Name')),
    "type": (basestring, 'Name'),
    "name": (basestring, 'Name'),
    "edges": (list, (basestring, (basestring, 'Item'))),
    "keys": (list, (basestring, 'Name')),
    "values": (list, (basestring, 'FreeForm'))
  }
}
