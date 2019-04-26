import sys
import os
import pprint
import json
import netaddr
import re
import time
import uuid
import urlparse
import BaseHTTPServer
import threading
import traceback

from dateutil import parser

from constants import job_input_classes, job_output_classes

global gHttpLock
global gHttpdDone
global gStatus
global gInputData
global gOutputData
global gErrorData

class JobDefinition():
  name = None
  description = None
  owner = None
  dockerUrl = None
  dockerUser = None
  command = None
  memoryUsage = None
  diskUsage = None
  processorUsage = None
  inputType = None
  events = None
  conditions = None
  outputTypes = None
  timeout = None

  def __init__(self, raw):
    try:
      self.name = raw['name']
      self.description = raw['description']
      self.owner = raw['owner']
      self.dockerUrl = raw['docker_url']
      self.dockerUser = raw['docker_user']
      self.command = raw['command']
      self.memoryUsage = raw['memory']
      self.diskUsage = raw['disk']
      self.processorUsage = raw['processor_usage']
      self.inputType = raw['input']
      self.events = raw['events']
      self.conditions = raw['conditions']
      self.outputTypes = raw['outputs']
      self.timeout = raw['timeout']
    except:
      raise Exception("The job definition given to the worker is malformed")

  def getDescription(self):
    return self.description

  def getName(self):
    return self.name

  def getOwner(self):
    return self.owner

  def getDockerUrl(self):
    return self.dockerUrl

  def getDockerUser(self):
    return self.dockerUser

  def getCommand(self):
    return self.command

  def getMemoryUsage(self):
    return self.memoryUsage

  def getDiskUsage(self):
    return self.diskUsage

  def getProcessorUsage(self):
    return self.processorUsage

  def getInputType(self):
    return self.inputType

  def getEvents(self):
    return self.events

  def getCondtions(self):
    return self.conditions

  def getOutputTypes(self):
    return self.outputTypes

  def getTimeout(self):
    return self.timeout



class RawInput():
  task = {}
  job = {}
  context = {}
  settings = {}
  objects = []
  input = None
  job_desc = None
  guid = None
  key = None

  def __init__(self, raw):
    try:
      self.task = json.loads(raw)
    except:
      raise Exception("The received task is improperly formatted: {}".format(str(raw)))
    
    if not "job" in self.task.keys():
      raise Exception("The received task does not contain a job description: {}".format(self.task))

    self.job = self.task["job"]
    if not "context" in self.task.keys():
      raise Exception("The received task does not contain any input: {}".format(self.task))

    self.context = self.task["context"]
    if not "type" in self.context.keys():
      raise Exception("The received input is not valid: {}".format(str(self.context)))

    if not "input" in self.job.keys():
      raise Exception("The received job contains invalid input: {}".format(str(self.job)))
    
    if not self.context["type"] == self.job["input"]:
      raise Exception("Input type mismatch. Job expects {}, got {}".format(self.job["input"], self.context["type"]))

    if not "guid" in self.task.keys() or not isinstance(self.task["guid"], basestring):
      raise Exception("The received task is improperly formatted and does not contain a worker guid: {}".format(self.task))

    self.guid = self.task["guid"]

    if not "key" in self.task.keys() or not isinstance(self.task["key"], basestring):
      raise Exception("The received task is improperly formatted and does not contain a task key: {}".format(self.task))

    self.key = self.task["key"]

    if "settings" in self.task.keys():
      try:
        self.settings = json.loads(self.task["settings"])
        if not isinstance(self.settings, dict):
          self.settings = {}
      except:
        # For now we just ignore bad project settings
        pass

    self.job_desc = JobDefinition(self.job)
    self.input = Item.fromContext(self)
    self.objects.append(self.input)

  def getInputType(self):
    return self.context["type"]

  def getInput(self):
    return self.input

  def getJob(self):
    return self.job_desc
  
  def findByUuid(self, uuid):
    for obj in self.objects:
      if obj.getUuid() == uuid:
        return obj
    return None

  def addItem(self, datatype, init_data):
    item = Item(datatype, self)
    if init_data:
      if not isinstance(init_data, dict):
        raise Exception("The item initialization data must be of type dict")
      for key in init_data.keys():
        item.setProperty(key, init_data[key])
    self.objects.append(item)
    return item

  def removeItem(self, uuid):
    found = False
    for obj in self.objects:
      if obj.getUuid() == uuid:
        self.objects.remove(obj)
        break
    if not found:
      raise Exception("Attempted to remove a non-existant object")

  def output(self):
    output = {
      "status": "success",
      "guid": self.guid,
      "key": self.key
    }
    for item in self.objects:
      item_type = item.getType()
      item_output = item.output()
      if not item_type in output.keys():
        output[item_type] = [item_output]
      else:
        output[item_type].append(item_output)
    return output

  def error(self, message):
    output = {
      "status": "failed",
      "guid": self.guid,
      "key": self.key,
      "msg": message
    }
    return output

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

# TODO(cdn): Introduce the concept of required fields on the various input objects. 
#            For example, currently if you submit a service with no Host set, the 
#            sort will fail on the server side. It would be better for the client 
#            library to warn you early that certain fields are required.
#            Similarly, we may want to make it so that when creating an object 
#            that requires a link to a higher level object, the higher level gets 
#            auto created. Ex. CreateObject("Service"...) also creates a Host object 
#            automatically

class Item():
  type = "Item"
  uuid = None
  data_store = None
  is_input = None
  properties = None

  def __init__(self, item_type, data_store):
    self.type = item_type
    self.properties = {}
    self.is_input = False
    if not isinstance(data_store, RawInput):
      raise Exception("The raw data store is corrupt")
    self.data_store = data_store
    self.uuid = uuid.uuid4().get_hex()

  @staticmethod
  def fromContext(data_store):
    input_item = data_store.context
    if not "type" in input_item.keys() or not input_item["type"] in job_input_classes.keys():
      raise Exception("Attempting to create input Item from malformed object: {}". format(str(input_item)))
    item = Item(input_item["type"], data_store)
    item.is_input = True
    for key in input_item.keys():
      value = input_item[key]
      if key in job_input_classes[item.type].keys():
        expected_type = job_input_classes[item.type][key]
        list_expected_type = None
        if isinstance(expected_type, tuple):
          expected_type = list
          list_expected_type = job_input_classes[item.type][key][1]
        if not value is None and not isinstance(value, expected_type):
          raise Exception("Attempting to create input Item of type {} with invalid property: name={} type={} expected type={}". format(item.type, str(key), str(type(value)), str(job_input_classes[item.type][key])))
        if not list_expected_type is None:
          for thing in value:
            if not isinstance(thing, list_expected_type):
              raise Exception("Attempting to create input Item of type {} with invalid property: name={} type={} expected type={}". format(item.type, str(key), str(type(thing)), str(list_expected_type)))
        item.properties[key] = value
      else:
        # Recieved extra context that is not currently handled, ignore it
        continue
    return item

  def getUuid(self):
    return self.uuid

  def getType(self):
    return self.type

  def getReadableProperties(self):
    if not self.type in job_input_classes.keys():
      return []
    props = job_input_classes[self.type]
    if not self.type == "Custom":
      return props
    props.remove("keys")
    props.remove("values")
    return props

  def getWritableProperties(self):
    if not self.type in job_output_classes.keys():
      return []
    props = job_output_classes[self.type]
    if not self.type == "Custom":
      return props
    props.remove("keys")
    props.remove("values")
    return props

  def getProperty(self, name):
    custom_prop = False
    if not name in job_input_classes[self.type].keys():
      if self.type == "Custom":
        custom_prop = True
      else:
        raise Exception("Attempting to get an invalid property on a {} object: {}".format(self.type, name))
    if custom_prop:
      if not "keys" in self.properties.keys() or not "values" in self.properties.keys():
        return None
      if not name in self.properties["keys"]:
        return None
      idx = self.properties["keys"].index(name)
      return self.properties["values"][idx]
    if not name in self.properties.keys():
      return None
    return self.properties[name]

  def validateType(self, datatype, dataformat, value):
    if isinstance(dataformat, tuple):
      _, dataformat = dataformat

    if isinstance(dataformat, list):
      if value in dataformat:
        return True
      return False
    elif isinstance(datatype, type) and not isinstance(value, datatype):
      return False
    validator = JobOutputValidators.getValidator(dataformat)
    if validator:
      return validator(value)

    ref = self.data_store.findByUuid(value)
    if not ref:
      return False
    if dataformat == "Item" or dataformat == ref.getType():
      return True
    return False
  
  def setProperty(self, name, value):
    custom_prop = False
    if not name in job_output_classes[self.type].keys():
      if self.type == "Custom":
        custom_prop = True
      else:
        raise Exception("Attempting to set an invalid property on a {} object: {}".format(self.type, name))
    if custom_prop:
      if not "keys" in self.properties.keys() or not "values" in self.properties.keys():
        self.properties["keys"] = []
        self.properties["values"] = []
      if not isinstance(name, basestring) or not isinstance(value, basestring):
        raise Exception("Attempted to set non-string custom property on object: Name type = {}, Value type = {}".format(str(type(name)), str(type(value))))
      self.properties["keys"].append(name)
      self.properties["values"].append(value)
      return
    expected_type, expected_format = job_output_classes[self.type][name]
    if expected_type == list:
      inner_expected_type, expected_format = expected_format
      if not isinstance(value, expected_type):
        raise Exception("Attempting to set property {} to an invalid type, expected {}, got {}".format(name, str(expected_type), str(type(value))))
      for item in value:
        if not self.validateType(inner_expected_type, expected_format, item):
          raise Exception("Attempting to set list property {} to a list that contains an invalid item type, expected type {}, expected format {}, got {}: item: {}".format(name, str(inner_expected_type), str(expected_format), str(type(item)), str(item)))
    else:
      if not self.validateType(expected_type, expected_format, value):
        raise Exception("Attempting to set property {} to an invalid value, expected type {}, expected format {}, got {}".format(name, str(expected_type), str(expected_format), str(value)))
    self.properties[name] = value
    return

  def output(self):
    out = self.properties
    out.update({ "uuid": self.getUuid() })
    return out

gHttpLock = threading.Lock()
gHttpdDone = False
gStatus = 0
gInputData = None
gOutputData = None
gErrorData = None

def GetInput():
  global gHttpLock
  global gStatus
  global gInputData
  gHttpLock.acquire()
  if gStatus == 1 and not gInputData is None:
    gStatus = 2
    gHttpLock.release()
    return gInputData
  gHttpLock.release()
  return None

def SetOutput(output):
  global gHttpLock
  global gStatus
  global gOutputData
  gHttpLock.acquire()
  gStatus = 3
  gOutputData = output
  gHttpLock.release()

def SetError(output):
  global gHttpLock
  global gStatus
  global gErrorData
  gHttpLock.acquire()
  gStatus = 4
  gErrorData = output
  gHttpLock.release()

class HttpService(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_GET(self):
    global gHttpLock
    global gStatus
    global gOutputData
    global gHttpdDone
    gHttpLock.acquire()
    if gStatus  == 0:
      self.send_response(418)
      self.send_header("Content-type", "application/json")
      self.end_headers()
      self.wfile.write(json.dumps({"status": "awaiting input"}))
      gHttpLock.release()
      return
    elif gStatus == 1 or gStatus == 2:
      self.send_response(202)
      self.send_header("Content-type", "application/json")
      self.end_headers()
      self.wfile.write(json.dumps({"status": "processing"}))
      gHttpLock.release()
      return
    elif gStatus == 3 and not gOutputData is None:
      self.send_response(200)
      self.send_header("Content-type", "application/json")
      self.end_headers()
      self.wfile.write(json.dumps(gOutputData))
      gHttpdDone = True
      gHttpLock.release()
      return
    else:
      self.send_response(408)
      self.send_header("Content-type", "application/json")
      self.end_headers()
      error = gErrorData if not gErrorData is None else {"status": "error"}
      self.wfile.write(json.dumps(error))
      gHttpdDone = True
      gHttpLock.release()
      return

  def do_POST(self):
    global gHttpLock
    global gStatus
    global gInputData
    global gHttpdDone
    gHttpLock.acquire()
    recved = self.rfile.read(int(self.headers['Content-Length']))
    if recved == "killswitch":
      self.send_response(200)
      self.send_header("Content-type", "application/json")
      self.end_headers()
      self.wfile.write(json.dumps({"status": "killed"}))
      gHttpdDone = True
      gHttpLock.release()
      return

    if not gStatus == 0:
      self.send_response(418)
      self.send_header("Content-type", "application/json")
      self.end_headers()
      self.wfile.write(json.dumps({"status": "confused"}))
      gHttpLock.release()
      return

    gInputData = recved
    gStatus = 1
    self.send_response(200)
    self.send_header("Content-type", "application/json")
    self.end_headers()
    self.wfile.write(json.dumps({"status": "accepted"}))
    gHttpLock.release()
    return

def _serve_http():
  global gHttpLock
  global gHttpdDone
  httpd = BaseHTTPServer.HTTPServer(('', 65050), HttpService)
  while True:
    httpd.handle_request()
    if gHttpdDone:
      break
  return


class DivergentTIPJob():
  runnable = None
  data_store = None
  httpd_thread = None

  def Process(self, input):
    raise NotImplementedError("The Process method is not implemented by the Job")

  def Start(self):
    self.httpd_thread = threading.Thread(target=_serve_http)
    self.httpd_thread.start()
    input_data = GetInput()
    while True:
      if input_data is None:
        time.sleep(1)
        input_data = GetInput()
        continue
      break

    try:
      self.data_store = RawInput(input_data)
      self.Process(self.data_store.getInput())
      self.ExitSuccess()
    except Exception:
      trace = traceback.format_exc()
      self.ExitFailure("The job threw an unhandled exception: {}".format(str(trace)))

  def CreateObject(self, datatype, properties):
    if not datatype in job_output_classes.keys():
      raise Exception("Attempting to create an output for an unsupported data type. Supported types are: {}".format(str(job_output_classes.keys())))
    if self.data_store is None:
      raise Exception("CreateObject() called before Start()")
    job = self.data_store.getJob()

    if not datatype in job.getOutputTypes() and not datatype == job.getInputType():
      raise Exception("Attempting to create a output for a data type that is not a valid output class for this job type. Supported types are: {}".format(str(job.getOutputTypes())))
    object = self.data_store.addItem(datatype, properties)
    return object

  def DeleteObject(self, object):
    if self.data_store is None:
      raise Exception("DeleteObject() called before Start()")
    if not isinstance(object, Item):
      raise Exception("Invalid argument, you must supply the object that was returned by a previous calll to CreateObject()")
    if object.is_input:
      raise Exception("Invalid argument, the input object can not be deleted")

    self.data_store.removeItem(object.getUuid())
    return

  def GetSetting(self, name):
    if self.data_store is None:
      raise Exception("GetSetting() called before Start()")
    
    if not name in self.data_store.settings.keys():
      return None
    return self.data_store.settings[name]

  def ExitSuccess(self):
    if self.data_store is None or self.httpd_thread is None:
      raise Exception("ExitSuccess() called before Start()")
    SetOutput(self.data_store.output())
    self.httpd_thread.join()

  def ExitFailure(self, message):
    if self.httpd_thread is None:
      raise Exception("ExitFailure() called before Start()")
    if self.data_store is None:
      output = {
        "status": "failed",
        "msg": message
      }
      SetError(output)
      self.httpd_thread.join()
    SetError(self.data_store.error(message))
    self.httpd_thread.join()

  # Utility function to get a CIDR from a first and last ip
  @staticmethod
  def IpAddressesToCIDR(firstIP, lastIP):
    fbin = bin(netaddr.IPAddress(firstIP).value)
    lbin = bin(netaddr.IPAddress(lastIP).value)
    offset = 2
    mask = 0
    while offset <= len(fbin) and offset <= len(lbin):
      if not fbin[offset] == lbin[offset]:
        break
      mask += 1
      offset += 1
    return firstIP + "/" + str(mask)

  @staticmethod
  def parseCookie(string):
    name = None
    value = None
    path = "/"
    domain = None
    secure = False
    httponly = False
    samesite = "lax"
    maxage = None

    directives = string.split(";")

    if directives[0].upper().startswith("SET-COOKIE:"):
      directives[0] = directives[0][11:]
    directives = [ directive.strip() for directive in directives ]

    name_val = directives[0].split("=")
    name = name_val[0]
    if len(name_val) > 1:
      value = name_val[1]

    for i in range(1, len(directives) - 1):
      directive = directives[i]
      if directive.upper() == "SECURE":
        secure = True
      elif directive.upper() == "HTTPONLY":
        httponly = True
      elif directive.upper().startswith("PATH="):
        path_parts = directive.split("=")
        path = path_parts[1] if len(path_parts) > 1 else "/"
      elif directive.upper().startswith("DOMAIN="):
        domain_parts = directive.split("=")
        domain = domain_parts[1] if len(domain_parts) > 1 else None
      elif directive.upper().startswith("SAMESITE="):
        samesite_parts = directive.split("=")
        samesite = "strict" if len(samesite_parts) > 1 and samesite_parts[1].upper() == "STRICT" else "lax"
      elif directive.upper().startswith("MAX-AGE="):
        maxage_parts = directive.split("=")
        try:
          maxage = int(maxage_parts[1]) if len(maxage_parts) > 1 else None
        except ValueError:
          maxage = None
    return {
      "name": name,
      "value": value,
      "path": path,
      "domain": domain,
      "secure": secure,
      "httponly": httponly,
      "samesite": samesite,
      "maxage": maxage
    }

  @staticmethod
  def getHostnameDomain(hostname):
    if hostname.endswith("."): # A single trailing dot is legal
      hostname = hostname[:-1] # strip exactly one dot from the right, if present
    parts = hostname.split(".")
    if len(parts) < 2 or not len(parts[-2]) or not len(parts[-1]):
      return None
    return parts[-2] + "." + parts[-1]