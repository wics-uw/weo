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

from weo.utils import get_user_password

# Kerberos-specific info
REALM = 'WICS.UWATERLOO.CA'
KRB_ADMIN = 'sysadmin/admin'


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
