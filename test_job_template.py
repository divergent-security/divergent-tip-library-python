import pytest

from job_template import *


class TestJob(DivergentTIPJob):
  def Process(self, input):
    self.ExitSuccess()


def test_networking():
  # Start the TestJob and make sure that the webserver comes up and show the right info and the right time
  return


def test_dns_hooks():
  # Start the TestJob and insert a dns hook, then reoslve a name using socket.getaddrinfo and make sure that we get the hooked value
  return
