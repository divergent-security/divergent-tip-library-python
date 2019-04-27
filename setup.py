from setuptools import setup

setup(name='divergent_tip_library_python',
      version='0.1',
      description="Python Job Library for Divergent Security's Threat Intelligence Platform",
      url='https://tip.divergentsecurity.com',
      author='Divergent Security',
      author_email='support@divergentsecurity.com',
      license='None',
      packages=[ 'divergent_tip_library' ],
      install_requires=[
          'netaddr',
          'dateutil'
      ],
      zip_safe=False)
