import netaddr
import re
import urlparse

from dateutil import parser

class JobOutputValidators():
  @staticmethod
  def validateCIDR(input):
    try:
      netaddr.IPNetwork(input)
    except:
      return False
    return True

  @staticmethod
  def validateIP(input):
    try:
      netaddr.IPAddress(input)
    except:
      return False
    return True

  @staticmethod
  def validateMAC(input):
    try:
      netaddr.EUI(input)
    except:
      return False
    return True

  @staticmethod
  def validateURLPath(input):
    try:
      #pylint: disable=unused-variable
      url = urlparse.urlparse(input)
    except:
      return False
    return 

  @staticmethod
  def validateResolvableName(input):
    hostname = input
    if hostname[-1] == ".":
      hostname = hostname[:-1]
    if len(hostname) > 253:
      return False
    labels = hostname.split(".")
    if re.match(r"[0-9]+$", labels[-1]):
        return False
    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)

  @staticmethod
  def validateName(input):
    allowed = re.compile(r"(?!-)[a-z0-9-_]{1,120}(?<!-)$", re.IGNORECASE)
    return allowed.match(input)

  @staticmethod
  def validateDateTime(input):
    try:
      parser.parse(input)
    except:
      return False
    return True

  DataTypeValidators = {
    'CIDR': validateCIDR.__func__,
    'IPAddress': validateIP.__func__,
    'MACAddress': validateMAC.__func__,
    'URLPath': validateURLPath.__func__,
    'Name': validateName.__func__,
    'DateTime': validateDateTime.__func__,
    'ResolvableName': validateResolvableName.__func__,
    'FreeForm': lambda input: True
  }

  @staticmethod
  def getValidator(datatype):
    if not datatype in JobOutputValidators.DataTypeValidators.keys():
      return None
    return JobOutputValidators.DataTypeValidators[datatype]

