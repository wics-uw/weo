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
import ldap
import ldap.modlist as modlist
import sys
import time
import traceback

# Debugging flags
VERBOSE = True
DEBUG = True

# Connection information
LDAP_SERVER = 'ldaps://auth1.wics.uwaterloo.ca'
UW_LDAP = 'ldap://ldap.uwaterloo.ca'

# LDAP-specific info
BASE = 'dc=wics,dc=uwaterloo,dc=ca'
ADMIN = 'cn=root,' + BASE
ADMIN_PW = getpass.getpass('Enter LDAP admin password: ')

# Timeout and retry values
NUM_TRIES = 3
SLEEP_DUR = 5


## Configurable logging ##

def verbose(statement):
    if VERBOSE is True:
        print '--> ',  # no newline
        print statement


def debug(statement):
    if DEBUG is True:
        print statement


def error(statement):
    # Error messages are always printed
    sys.stderr.write(statement + '\n')


def print_exc(exc_info):
    (exc, msg, st) = exc_info
    error('Encountered exception: %s %s\n%s' %
          (exc, msg, traceback.format_exc(st)))


## LDAP interface for the WiCS LDAP DB ##
class wics_ldap(object):
    def __init__(self):
        # Open LDAP connection
        self.ldap_wics = ldap.initialize(LDAP_SERVER)
        self.ldap_uw = ldap.initialize(UW_LDAP)  # FIXME: currently unused

        # FIXME: This gives admin access for all the things; fine for now, will
        # not be fine later.
        self.ldap_wics.bind_s(ADMIN, ADMIN_PW)

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
        att: the attribute we are modifying (e.g. uid or cn)
        '''
        self.ldap_wics.modrdn_s(dn, newdn)
        debug('Unlocked database.')

    def add_user(self, uid, username):
        '''
        Adds a user to the LDAP database.

        uid: the unique user id for our new user
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

        attrs = {
            #'uid': uid,
            'cn': username,
            'objectClass': ['account', 'member', 'posixAccount',
                            'shadowAccount', 'top'],
            'homeDirectory': '/home/' + uid,
            'uidNumber': str(next_uid),
            'gidNumber': str(next_gid),
            # 'program': program,  TODO: add query to uwldap for autocompletion
            # 'cn': name,
            # 'term': ...
        }

        try:
            # FIXME: can we make this atomic with the next operation at the
            # LDAP level?
            self.ldap_wics.modify_s(
                'uid=inuse,ou=People,' + BASE,
                [(ldap.MOD_REPLACE, 'uidNumber', str(next_uid + 1)),
                 (ldap.MOD_REPLACE, 'gidNumber', str(next_gid + 1))])

            debug('Adding user...')
            verbose('dn: uid=%s,ou=People,%s' % (uid, BASE))
            ml = modlist.addModlist(attrs)
            verbose('modlist: ')
            verbose(ml)

            self.ldap_wics.add_s('uid=%s,ou=People,%s' % (uid, BASE), ml)

        except:
            print_exc(sys.exc_info())
            error('Failed to add user!')

            # Reset UID/GID before unlocking
            self.ldap_wics.modify_s(
                'uid=inuse,ou=People,' + BASE,
                [(ldap.MOD_REPLACE, 'uidNumber', str(next_uid)),
                 (ldap.MOD_REPLACE, 'gidNumber', str(next_gid))])

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
            # FIXME: can we make this atomic with the next operation at the
            # LDAP level?
            self.ldap_wics.modify_s(
                'cn=inuse,ou=Group,' + BASE,
                [(ldap.MOD_REPLACE, 'gidNumber', str(next_gid + 1))])

            debug('Adding group...')
            verbose('dn: cn=%s,ou=Group,%s' % (gid, BASE))
            ml = ldap.modlist.addModlist(attrs)
            verbose('modlist: ')
            verbose(ml)

            self.ldap_wics.add_s('cn=%s,ou=Group,%s' % (gid, BASE), ml)

        except:
            print_exc(sys.exc_info())
            error('Failed to add group!')

            # Reset GID before unlocking
            self.ldap_wics.modify_s(
                'cn=inuse,ou=Group,' + BASE,
                [(ldap.MOD_REPLACE, 'gidNumber', str(next_gid))])

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
            verbose('modlist: ')
            verbose(ml)

            self.ldap_wics.modify_s('cn=%s,ou=Group,%s' % (gid, BASE), ml)
        except:
            print_exc(sys.exc_info())
            error('Failed to add user to group!')


if __name__ == '__main__':
    import getopt

    # Get opt returns options and arguments, but we take no arguments
    (opts, _) = getopt.getopt(
        sys.argv[1:],
        '',
        [
            'unlock-nextuid',
            'unlock-nextgid',
            'adduser',
            'addgroup',
            'add-user-to-group',
            'username=',
            'fullname=',
            'groupname=',
            'groupdesc=',
        ])

    opts = dict(opts)
    verbose(str(opts))

    if '--adduser' in opts:
        if opts.get('--username') and opts.get('--fullname'):
            username = opts['--username']
            debug('Okay, adding user %s' % username)

            l = wics_ldap()
            l.add_user(username, opts['--fullname'])
            debug('User %s successfully added.' % username)
            sys.exit(0)

    if '--addgroup' in opts:
        if opts.get('--groupname') and opts.get('--groupdesc'):
            groupname = opts['--groupname']
            debug('Okay, adding group %s' % groupname)

            l = wics_ldap()
            l.add_group(groupname, opts['--groupdesc'])
            debug('Group %s successfully added.' % groupname)
            sys.exit(0)

    if '--add-user-to-group' in opts:
        if opts.get('--username') and opts.get('--groupname'):
            username = opts['--username']
            groupname = opts['--groupname']
            debug('Okay, adding user %s to group %s' % (username, groupname))

            l = wics_ldap()
            l.add_user_to_group(groupname, username)
            debug('User %s successfully added to group %s' %
                  (username, groupname))
            sys.exit(0)

    if '--unlock-nextuid' in opts:
        l = wics_ldap()
        l.unlock('uid=inuse,ou=People,' + BASE, 'uid=nextuid')

    if '--unlock-nextgid' in opts:
        l = wics_ldap()
        l.unlock('cn=inuse,ou=Group,' + BASE, 'cn=nextgid')
