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

import datetime
import getpass

## Utility functions ##

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


def get_term(date=None):
    "Returns the current term by checking the date"
    today = date

    if date is None:
        today = datetime.date.today()

    month = today.month
    year = today.year

    if month < 5:
        return 'w' + str(year)
    elif month < 9:
        return 's' + str(year)
    else:  # month <= 12
        return 'f' + str(year)
