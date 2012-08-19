from distutils.core import setup

setup(
    name='PyDomainAlyzer',
    version='1.0.0',
    author='Andy Newton',
    author_email='amn@ecs.soton.ac.uk',
    packages=['domainalyzer'],
    scripts=['bin/domainalyzer-tool.py'],
    #url='http://pypi.python.org/pypi/PyDomainAlyzer/',
    license='LICENCE.txt',
    description='DNS zone analysis and problem reporting library and tools.',
    long_description=open('README.txt').read(),

    requires=[
        "dnspython (>=1.9.4)",
        "IPy (>=0.75)",
    ],

)

