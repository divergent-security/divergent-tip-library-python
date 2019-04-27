from setuptools import setup

setup(name='divergent_tip_job_library',
      version='0.1',
      description="Python Job Library for Divergent Security's Threat Intelligence Platform",
      url='https://tip.divergentsecurity.com',
      author='Divergent Security',
      author_email='support@divergentsecurity.com',
      license='None',
      packages=[ 'divergent_tip_library_python' ],
      install_requires=[
          'netaddr',
          'urlparse'
      ],
      zip_safe=False)
