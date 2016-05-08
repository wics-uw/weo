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

import sys
import traceback


# Debugging flags

VERBOSE = False
DEBUG = True
DAS_ERROR = False


# Configurable logging

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
