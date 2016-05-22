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

from __future__ import absolute_import


import datetime
import getpass
import ldap
import ldap.modlist as modlist
import ldap.sasl
import sys
import time

from dateutil.relativedelta import relativedelta
from weo.log import debug, error, print_exc, verbose
from weo.utils import get_term

# Connection information
LDAP_SERVER = 'ldaps://auth1.wics.uwaterloo.ca'
UW_LDAP = 'ldap://ldap.uwaterloo.ca'

# LDAP-specific info
BASE = 'dc=wics,dc=uwaterloo,dc=ca'
LDAP_ADMIN = 'cn=root,' + BASE

# Timeout and retry values
NUM_TRIES = 3
SLEEP_DUR = 5


class wics_ldap(object):
    'LDAP interface for the WiCS LDAP DB'

    def __init__(self):
        # Open LDAP connection
        self.ldap_wics = ldap.initialize(LDAP_SERVER)
        self.ldap_uw = ldap.initialize(UW_LDAP)  # FIXME: currently unused

        # FIXME: This gives admin access for all the things; fine for now, will
        # not be fine later.
        auth = ldap.sasl.gssapi("")
        self.ldap_wics.sasl_interactive_bind_s("", auth)

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

        current_term = get_term()

        attrs_user = {
            # 'uid': uid,
            'cn': username,
            'objectClass': ['account', 'member', 'posixAccount',
                            'shadowAccount', 'top'],
            'homeDirectory': '/home/' + uid,
            'loginShell': '/bin/bash',
            'uidNumber': str(next_uid),
            'gidNumber': str(next_gid),
            'term': current_term,
            # 'program': program,  TODO: add query to uwldap for autocompletion
            # 'cn': name,
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
            ml = modlist.addModlist(attrs_grp)
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
            ml = modlist.addModlist(attrs)
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

    def renew_user(self, uid, num_terms=None):
        "Renews the user 'uid' for the current term, or a number of terms."
        if num_terms is None:
            num_terms = 1
        if num_terms > 3:
            debug('Warning: I can only renew a member for up to 3 terms at a '
                  'time! I will renew for the maximum possible number.')
            term = 3
        if num_terms < 1:
            error("Your number of terms doesn't make any sense! You said: %s" %
                  num_terms)
            return

        terms = []
        for num in range(num_terms):
            terms.append(get_term(datetime.date.today() +
                         relativedelta(months=(num * 4))))

        for term in terms:
            try:
                debug('Renewing user for term ' + term)
                verbose('dn: uid=%s,ou=People,%s' % (uid, BASE))
                ml = [(ldap.MOD_ADD, 'term', term)]
                verbose('modlist: ' + str(ml))

                self.ldap_wics.modify_s('uid=%s,ou=People,%s' % (uid, BASE),
                                        ml)
            except:
                print_exc(sys.exc_info())
                error('Failed to renew user for term ' + term + '!')
