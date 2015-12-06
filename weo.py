# Copyright (C) 2015 Elana Hashman
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

import getpass
import kadmin
import ldap
import ldap.modlist as modlist
import sys
import time
import traceback

# Debugging flags
VERBOSE = False
DEBUG = True
DAS_ERROR = False

# Connection information
LDAP_SERVER = 'ldaps://auth1.wics.uwaterloo.ca'
UW_LDAP = 'ldap://ldap.uwaterloo.ca'

# LDAP-specific info
BASE = 'dc=wics,dc=uwaterloo,dc=ca'
LDAP_ADMIN = 'cn=root,' + BASE

# Kerberos-specific info
REALM = 'WICS.UWATERLOO.CA'
KRB_ADMIN = 'sysadmin/admin'

# Timeout and retry values
NUM_TRIES = 3
SLEEP_DUR = 5


## Configurable logging ##

def verbose(statement):
    "Prints the message 'statement' if verbose debugging is turned on"
    if VERBOSE is True:
        print '--> ',  # no newline
        print statement


def debug(statement):
    "Prints the message 'statement' if debugging is turned on"
    if DEBUG is True:
        print statement


def error(statement):
    "Prints the error message 'statement' to standard error"
    global DAS_ERROR
    DAS_ERROR = True

    # Error messages are always printed
    sys.stderr.write(statement + '\n')


def print_exc(exc_info):
    "Prints the contents of an exception info object, exc_info"
    (exc, msg, st) = exc_info
    error('Encountered exception: %s %s\n%s' %
          (exc, msg, traceback.format_exc(st)))


def exit_with_msg(on_failure, on_success):
    '''
    Exits with correct message and exit code depending on whether an error was
    encountered

    on_failure: the failure message
    on_success: the success message
    '''
    if DAS_ERROR:
        error(on_failure)
        sys.exit(1)
    else:
        debug(on_success)
        sys.exit(0)


def get_user_password(message):
    '''
    Prompts the user, with notice 'message', for a password on standard input,
    and checks to ensure the provided passwords match.
    '''
    pwd_attempt1 = getpass.getpass(message)
    pwd_attempt2 = getpass.getpass('Retype password: ')

    if pwd_attempt1 == pwd_attempt2:
        return pwd_attempt1
    else:
        raise ValueError("Passwords don't match!")


def check_username(uid, maxlen=8):
    '''
    Validates a username 'uid' by ensuring it consists of lowercase ASCII
    characters, between 3 and 'maxlen' characters in length.
    '''
    if uid.islower() and len(uid) <= maxlen and len(uid) >= 3:
        return uid
    else:
        raise ValueError(
            'IDs must be 3-%d lowercase ASCII characters, received %s' %
            (maxlen, uid))


## Kerberos interface for the WiCS Kerberos Realm ##
class wics_krb5(object):
    def __init__(self):
        # Open Kerberos admin connection
        self.krb_wics = kadmin.init_with_password(
            '%s@%s' % (KRB_ADMIN, REALM),
            getpass.getpass('Enter Kerberos admin password: '))

    def add_princ(self, uid, password=None):
        '''
        Adds a Kerberos principal.

        uid: the user id for the principal
        password: (optional) a string consisting of the user's password; if no
            string is provided the user will be prompted to enter one
        '''
        if password is None:
            password = get_user_password(
                'Enter password for principal %s@%s: ' % (uid, REALM))

        debug('Adding Kerberos principal...')
        self.krb_wics.addprinc('%s@%s' % (uid, REALM), password)


## LDAP interface for the WiCS LDAP DB ##
class wics_ldap(object):
    def __init__(self):
        # Open LDAP connection
        self.ldap_wics = ldap.initialize(LDAP_SERVER)
        self.ldap_uw = ldap.initialize(UW_LDAP)  # FIXME: currently unused

        # FIXME: This gives admin access for all the things; fine for now, will
        # not be fine later.
        self.ldap_wics.bind_s(
            LDAP_ADMIN,
            getpass.getpass('Enter LDAP admin password: '))

    def lock(self, dn, newdn):
        '''
        This helper performs a simple atomic test and set lock using LDAP
        attributes.

        dn: the distinguished name of our mutex object
        newdn: new distinguished name object, e.g. "cn=newuid"
        '''
        debug('Locking LDAP database...')
        for x in range(NUM_TRIES):
            try:
                self.ldap_wics.modrdn_s(dn, newdn)
                return
            except:
                print_exc(sys.exc_info())
                time.sleep(SLEEP_DUR)

        raise ldap.TIMEOUT('Could not obtain lock on ' + dn)

    def unlock(self, dn, newdn):
        '''
        This helper performs an unlock using LDAP attributes.

        dn: the distinguished name of our mutex object
        newdn: new distinguished name object, e.g. "cn=newuid"
        '''
        self.ldap_wics.modrdn_s(dn, newdn)
        debug('Unlocked database.')

    def add_user(self, uid, username):
        '''
        Adds a user to the LDAP database.

        uid: the unique user id for our new user
        username: the user's full name
        '''
        self.lock('uid=nextuid,ou=People,' + BASE, 'uid=inuse')
        nextuid = self.ldap_wics.search_s(
            'uid=inuse,ou=People,' + BASE,
            ldap.SCOPE_BASE)

        nextuid_obj = nextuid[0][1]
        next_uid = int(nextuid_obj['uidNumber'][0])
        next_gid = int(nextuid_obj['gidNumber'][0])

        if next_uid != next_gid:
            # This isn't enforced at the schema level but close enough
            raise ldap.OBJECT_CLASS_VIOLATION(
                "UID and GID on nextuid are out of sync. Tell the sysadmin!")

        attrs_user = {
            #'uid': uid,
            'cn': username,
            'objectClass': ['account', 'member', 'posixAccount',
                            'shadowAccount', 'top'],
            'homeDirectory': '/home/' + uid,
            'loginShell': '/bin/bash',
            'uidNumber': str(next_uid),
            'gidNumber': str(next_gid),
            # 'program': program,  TODO: add query to uwldap for autocompletion
            # 'cn': name,
            # 'term': ...
        }

        attrs_grp = {
            'cn': uid,
            'objectClass': ['group', 'posixGroup', 'top'],
            'gidNumber': str(next_gid),
        }

        try:
            self.ldap_wics.modify_s(
                'uid=inuse,ou=People,' + BASE,
                [(ldap.MOD_REPLACE, 'uidNumber', str(next_uid + 1)),
                 (ldap.MOD_REPLACE, 'gidNumber', str(next_gid + 1))])

            debug('Adding user...')
            verbose('dn: uid=%s,ou=People,%s' % (uid, BASE))
            ml = modlist.addModlist(attrs_user)
            verbose('modlist: ' + str(ml))

            self.ldap_wics.add_s('uid=%s,ou=People,%s' % (uid, BASE), ml)

            debug("Adding user's group...")
            verbose('dn: cn=%s,ou=Group,%s' % (uid, BASE))
            ml = ldap.modlist.addModlist(attrs_grp)
            verbose('modlist: ' + str(ml))

            self.ldap_wics.add_s('cn=%s,ou=Group,%s' % (uid, BASE), ml)

        except:
            print_exc(sys.exc_info())
            error('Failed to add user!')

            # Reset UID/GID before unlocking
            self.ldap_wics.modify_s(
                'uid=inuse,ou=People,' + BASE,
                [(ldap.MOD_REPLACE, 'uidNumber', str(next_uid)),
                 (ldap.MOD_REPLACE, 'gidNumber', str(next_gid))])

        finally:
            self.unlock('uid=inuse,ou=People,' + BASE, 'uid=nextuid')

    def add_group(self, gid, desc):
        '''
        Adds a group to the LDAP database.

        gid: the unique group id for our new group
        desc: a longer, descriptive name for the group
        '''
        self.lock('cn=nextgid,ou=Group,' + BASE, 'cn=inuse')
        nextgid = self.ldap_wics.search_s(
            'cn=inuse,ou=Group,' + BASE,
            ldap.SCOPE_BASE)

        nextgid = nextgid[0][1]
        next_gid = int(nextgid['gidNumber'][0])

        attrs = {
            'cn': gid,
            'objectClass': ['group', 'posixGroup', 'top'],
            'gidNumber': str(next_gid),
            'description': desc,
        }

        try:
            self.ldap_wics.modify_s(
                'cn=inuse,ou=Group,' + BASE,
                [(ldap.MOD_REPLACE, 'gidNumber', str(next_gid + 1))])

            debug('Adding group...')
            verbose('dn: cn=%s,ou=Group,%s' % (gid, BASE))
            ml = ldap.modlist.addModlist(attrs)
            verbose('modlist: ' + str(ml))

            self.ldap_wics.add_s('cn=%s,ou=Group,%s' % (gid, BASE), ml)

        except:
            print_exc(sys.exc_info())
            error('Failed to add group!')

            # Reset GID before unlocking
            self.ldap_wics.modify_s(
                'cn=inuse,ou=Group,' + BASE,
                [(ldap.MOD_REPLACE, 'gidNumber', str(next_gid))])

        finally:
            self.unlock('cn=inuse,ou=Group,' + BASE, 'cn=nextgid')

    def add_user_to_group(self, gid, uid):
        '''
        Adds a user to an LDAP group.

        gid: the group to add the user to
        uid: the user to add to the group
        '''
        try:
            debug('Adding user to group...')
            verbose('dn: cn=%s,ou=Group,%s' % (gid, BASE))
            ml = [(ldap.MOD_ADD, 'uniqueMember',
                  'uid=%s,ou=People,%s' % (uid, BASE))]
            verbose('modlist: ' + str(ml))

            self.ldap_wics.modify_s('cn=%s,ou=Group,%s' % (gid, BASE), ml)
        except:
            print_exc(sys.exc_info())
            error('Failed to add user to group!')

    def remove_user_from_group(self, gid, uid):
        '''
        Removes a user from an LDAP group.

        gid: the group to remove the user from
        uid: the user to remove from the group
        '''
        try:
            debug('Removing user from group...')
            verbose('dn: cn=%s,ou=Group,%s' % (gid, BASE))
            ml = [(ldap.MOD_DELETE, 'uniqueMember',
                  'uid=%s,ou=People,%s' % (uid, BASE))]
            verbose('modlist: ' + str(ml))

            self.ldap_wics.modify_s('cn=%s,ou=Group,%s' % (gid, BASE), ml)
        except:
            print_exc(sys.exc_info())
            error('Failed to remove user from group!')


if __name__ == '__main__':
    import getopt

    # getopt returns options and arguments, but we take no arguments
    (opts, _) = getopt.getopt(
        sys.argv[1:],
        'hv',
        [
            'help',
            'unlock-nextuid',
            'unlock-nextgid',
            'add-ldap-user',
            'add-krb-princ',
            'adduser',
            'addgroup',
            'add-user-to-group',
            'remove-user-from-group',
            'username=',
            'fullname=',
            'groupname=',
            'groupdesc=',
        ])

    opts = dict(opts)
    if '-v' in opts:
        VERBOSE = True

    verbose('opts: ' + str(opts))

    if '--help' in opts or '-h' in opts:
        print '''
Usage: python weo.py [OPTIONS...]

  -h, --help    Prints this help message
  -v            Turns on verbose mode

  Standard commands
  -----------------
  --adduser                 Adds a user. Must also specify
                            --username and --fullname
  --addgroup                Adds a group. Must also specify
                            --groupname and --groupdesc
  --add-user-to-group       Adds a user to a group. Must also specify
                            --groupname and --username
  --remove-user-from-group  Removes a user from a group. Must
                            also specify --groupname and --username

  Parameters:
  --username=[name]         A user's id. Must be 3-8 lowercase ASCII
                            characters.
  --fullname=["N. Ame"]     A user's full name. Use quotes if it
                            contains spaces.
  --groupname=[name]        A group's id. Must be 3-10 lowercase ASCII
                            characters.
  --groupdesc=["D. esc"]    A group's description. Use quotes if it
                            contains spaces.

  Advanced commands
  -----------------
  LDAP Only:
  --add-ldap-user           Adds a user to the LDAP database. Must also
                            specify --username and --fullname
  --unlock-nextuid          Unlocks the special nextuid user.
  --unlock-nextgid          Unlocks the special nextgid group.

  Kerberos Only:
  --add-krb-princ           Adds a Kerberos principal for a user. Must
                            also specify --username
'''
        sys.exit(0)

    if '--add-ldap-user' in opts:
        if opts.get('--username') and opts.get('--fullname'):
            username = check_username(opts['--username'])
            debug('Okay, adding user %s' % username)

            l = wics_ldap()
            l.add_user(username, opts['--fullname'])

            exit_with_msg(
                'Failed to add user %s :(' % username,
                'User %s successfully added.' % username)

    if '--add-krb-princ' in opts:
        if opts.get('--username'):
            username = check_username(opts['--username'])
            debug('Okay, adding Kerberos principal %s@%s' % (username, REALM))

            k = wics_krb5()
            k.add_princ(username)

            exit_with_msg(
                'Failed to add Kerberos principal %s@%s :(' % (username, REALM),
                'Principal %s@%s successfully added.' % (username, REALM))

    if '--adduser' in opts:
        if opts.get('--username') and opts.get('--fullname'):
            username = check_username(opts['--username'])
            debug('Okay, adding user %s' % username)

            # Throws an exception before opening LDAP/KRB connections
            # if passwords don't match
            password = get_user_password(
                "Please enter the new user's password: ")

            l = wics_ldap()
            k = wics_krb5()
            l.add_user(username, opts['--fullname'])
            k.add_princ(username, password=password)

            exit_with_msg(
                'Failed to add user %s :(' % username,
                'User %s successfully added.' % username)

    if '--addgroup' in opts:
        if opts.get('--groupname') and opts.get('--groupdesc'):
            groupname = check_username(opts['--groupname'], maxlen=10)
            debug('Okay, adding group %s' % groupname)

            l = wics_ldap()
            l.add_group(groupname, opts['--groupdesc'])

            exit_with_msg(
                'Failed to add group %s :(' % groupname,
                'Group %s successfully added.' % groupname)

    if '--add-user-to-group' in opts:
        if opts.get('--username') and opts.get('--groupname'):
            username = opts['--username']
            groupname = opts['--groupname']
            debug('Okay, adding user %s to group %s' % (username, groupname))

            l = wics_ldap()
            l.add_user_to_group(groupname, username)

            exit_with_msg(
                'Failed to add user %s to group %s :(' % (username, groupname),
                'User %s successfully added to group %s' %
                (username, groupname))

    if '--remove-user-from-group' in opts:
        if opts.get('--username') and opts.get('--groupname'):
            username = opts['--username']
            groupname = opts['--groupname']
            debug('Okay, removing user %s from group %s' %
                  (username, groupname))

            l = wics_ldap()
            l.remove_user_from_group(groupname, username)

            exit_with_msg(
                'Failed to remove user %s from group %s :(' %
                (username, groupname),
                'User %s successfully removed from group %s' %
                (username, groupname))

    if '--unlock-nextuid' in opts:
        l = wics_ldap()
        l.unlock('uid=inuse,ou=People,' + BASE, 'uid=nextuid')
        sys.exit(0)

    if '--unlock-nextgid' in opts:
        l = wics_ldap()
        l.unlock('cn=inuse,ou=Group,' + BASE, 'cn=nextgid')
        sys.exit(0)
