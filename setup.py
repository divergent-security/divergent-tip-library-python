from setuptools import setup

setup(name='divergent_tip_job_library',
      version='0.1',
      description="Job Template's for Divergent Security's Threat Intelligence Portal",
      url='https://tip.divergentsecurity.com',
      author='Divergent Security',
      author_email='support@divergentsecurity.com',
      license='MIT',
      packages=[ 'divergent_tip_job_library' ],
      install_requires=[
          'netaddr'
      ],
      zip_safe=False)