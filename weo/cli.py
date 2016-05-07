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

import getopt
import sys
import traceback

from weo.krb5 import wics_krb5
from weo.ldap import wics_ldap
from weo.utils import check_username, get_user_password

# Debugging flags
VERBOSE = False
DEBUG = True
DAS_ERROR = False


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


def main():
    'CLI dispatch logic'

    def print_usage():
        print '''
Usage: python weo.py [OPTIONS...]

  -h, --help    Prints this help message
  -v            Turns on verbose mode

  Standard commands
  -----------------
  --renew                   Renews a user's account. Can optionally
                            specify number of terms, up to three (i.e.
                            --num-terms=2). Must specify --username
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
  --groupdesc=["D Esc"]     A group's description. Use quotes if it
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
            'renew',
            'username=',
            'fullname=',
            'groupname=',
            'groupdesc=',
            'num-terms=',
        ])



    opts = dict(opts)
    if '-v' in opts:
        VERBOSE = True

    verbose('opts: ' + str(opts))

    if not opts or '--help' in opts or '-h' in opts:
        print_usage()
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

    if '--renew' in opts:
        if opts.get('--username'):
            username = opts['--username']
            num_terms = opts.get('--num-terms')

            l = wics_ldap()
            if num_terms is not None:
                debug('Okay, renewing user %s for %s terms' %
                      (username, num_terms))
                l.renew_user(username, num_terms=int(num_terms))
            else:
                debug('Okay, renewing user %s' % username)
                l.renew_user(username)

            exit_with_msg(
                'Failed to renew user %s for specified terms :(' % username,
                'User %s successfully renewed!' % username)

    if '--unlock-nextuid' in opts:
        l = wics_ldap()
        l.unlock('uid=inuse,ou=People,' + BASE, 'uid=nextuid')
        sys.exit(0)

    if '--unlock-nextgid' in opts:
        l = wics_ldap()
        l.unlock('cn=inuse,ou=Group,' + BASE, 'cn=nextgid')
        sys.exit(0)

if __name__ == '__main__':
    main()
