# `weo`: WiCS Electronic Office

A python interface for LDAP and Kerberos.

## Dependencies ##

Install system-wide dependencies with aptitude:

```
# apt-get install libldap2-dev libsasl2-dev libkrb5-dev
```

Install Python dependencies in a virtualenv:

```
mkdir -p ~/virtualenvs/weo/
cd ~/virtualenvs/weo/
virtualenv .
source bin/activate
pip install -e .
```

## Building ##

To build this package, run

```
python setup.py build
```

If you want to install it in the active virtualenv for testing, you can use

```
python setup.py install
```

### Debian ###

To build the Debian package, run

```
dpkg-buildpackage -us -uc
```

Then you can install the .deb place in the directory one level above the
working directory on a debian-based system, i.e.

```
dpkg -i weo_0.0.1_amd64.deb
```
