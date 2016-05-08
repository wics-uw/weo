import setuptools

setuptools.setup(
    name='weo',
    version='0.0.2',
    description='WiCS Electronic Office',
    url='https://github.com/wics-uw/weo',
    author='Elana Hashman',
    author_email='ehashman@wics.uwaterloo.ca',
    maintainer='Women in Computer Science Systems Committee',
    maintainer_email='wics-sys@lists.uwaterloo.ca',
    license='GPLv2',
    classifiers=[
        'Development Status :: 4 - Beta',	
        'Intended Audience :: End Users/Desktop',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='weo',
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': [
            'weo=weo.cli:main',
        ]
    },
    install_requires=[
        'python-ldap',
        'python-kadmin',
        'python-dateutil',
    ],
)
