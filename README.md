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
pip install -r requirements.txt
```
