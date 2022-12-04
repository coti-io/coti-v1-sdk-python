from setuptools import setup, find_packages


setup(
    name='coti_wallet',
    description='coti wallet sdk for python',
    version='0.0.1b13',
    license='MIT',
    author="coti team",
    author_email='support@coti.io',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/coti-io/coti-sdk-python',
    keywords='coti wallet sdk',
    install_requires=[
          'urllib3', 'ecdsa', 'pycryptodome'
      ],

)