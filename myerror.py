import configparser
import inspect

config = None

class MyError():

  def __init__(self, et):
    self.config = configparser.RawConfigParser()
    self.config.read('ErrorMessages.properties')
    self.errorType = et

  def newError(self, koption, key, line=None, column=None, **data):
    message = ''
  
    if koption:
      return key
    else:
      if line is not None and column is not None:
        message = message + f"Erro[{line}][{column}]: "
      if key:
        message = message + self.config.get(self.errorType, key)
      if data:
        for key, value in data.items():
          message = message + ", " f"{key}: {value}"

    # print(message)
      return message.strip()

