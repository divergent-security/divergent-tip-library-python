import re
import pickle

from constants import job_input_classes, job_output_classes, event_types, conditional_operations

def compile(raw, datatype):
  if not datatype in job_input_classes.keys():
    return "An invalid condition was detected (The supplied input data type is invalid): " + datatype, None

  parts = raw.split(" ")
  if not parts or not len(parts):
    return "An invalid condition was detected (condition badly formated): " + raw, None
    
  operation = parts[0].upper()
  if not operation in conditional_operations.keys():
    return "An invalid condition was detected (operation type not supported): " + raw, None

  tokens_expected = conditional_operations[operation]
  if len(parts) < tokens_expected:
    return "An invalid condition was detected (not enough arguments for operation): " + raw, None
  if len(parts) > tokens_expected:
    # The immediate value at the end may contain spaces, join these parts into one string
    parts[tokens_expected - 1] = " ".join(parts[tokens_expected - 1:])
    parts = parts[:tokens_expected]

  field = parts[1].lower()
  if not datatype == "Custom" and not field in job_input_classes[datatype]:
    if not field in job_input_classes[datatype].keys():
      return "An invalid condition was detected (the supplied field name is not valid for the job input data type): " + raw, None

  regex = None
  immediate = None
  if operation in ["EQUAL", "LESS", "MORE", "MATCHES", "LIST-MATCH", "LIST-NO-MATCH"]:
    immediate = parts[2]
    if operation in ["MATCHES", "LIST-MATCH", "LIST-NO-MATCH"]:
      try:
        regex = re.compile(immediate)
      except:
        return "An invalid condition was detected (The regex immediate on a MATCH operation failed to compile): " + raw, None
      if operation in ["LIST-MATCH", "LIST-NO-MATCH"]:
        if not job_input_classes[datatype][field] == tuple or not job_input_classes[datatype][field][0] == list:
          return "An invalid condition was detected (the supplied operation must operate on a list field): " + raw, None
      else:
        if not job_input_classes[datatype][field] in [basestring,int,bool]:
          return "An invalid condition was detected (the supplied operation must operate on a string,  integer, or boolean field): " + raw, None
    
    elif operation in ["LESS", "MORE"]:
      if not job_input_classes[datatype][field] == int:
        return "An invalid condition was detected (the supplied field name is not a valid type for this operation): " + raw, None
      try:
        #pylint: disable=unused-variable
        ignore = int(immediate)
      except:
        return "An invalid condition was detected (the immediate value is not of type int): " + raw, None
    elif operation == "EQUAL":
      if job_input_classes[datatype][field] == int:
        try:
          ignore = int(immediate)
        except:
          return "An invalid condition was detected (the immediate value is not of type int): " + raw, None
      elif job_input_classes[datatype][field] == bool:
        if not immediate.upper() in ["TRUE", "FALSE"]:
          return "An invalid condition was detected (the immediate value is not a boolean true|false): " + raw, None
        immediate = immediate.upper()
      elif not job_input_classes[datatype][field] == basestring:
        return "An invalid condition was detected (The supplied field is not a valid type for an EQUAL operation): " + raw, None
  elif operation in ["TRUE", "FALSE"]:
    if not job_input_classes[datatype][field] == bool:
      return "An invalid condition was detected (the supplied operation must operate on a boolean field): " + raw, None
  elif operation == "EXISTS":
    if not datatype == "Custom" and not job_input_classes[datatype].has_key(field):
      return "An invalid condition was detected (the supplied operation must operate on Custom data type or a field that exists for the given type): " + raw, None
  if datatype == "Custom":
    if not operation in ["EXISTS", "EQUAL", "CHANGE", "LESS", "MORE", "MATCHES", "TRUE", "FALSE"]:
      return "An invalid condition was detected (the supplied operation is not supported on Custom data types): " + raw, None
    
  re_blob = None
  if operation in ["MATCHES", "LIST-MATCH", "LIST-NO-MATCH"]:
    try:
      re_blob = pickle.dumps(regex)
    except:
      return "An invalid condition was detected (Failed to serialize the compiled regular expression): " + raw, None
  try:
    return None, {'raw':raw, 'datatype':datatype, 'operation':operation, 'field':field, 'immediate':immediate, 'regex':re_blob}
  except:
    return "An invalid condition was detected (Failed to build the condition object): " + raw, None
