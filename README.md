# pa-effective-permission-calculator
Calculates the effective permissions a user has on a specific resource, taking into account group memberships, the file mode bits that match the user's relation to the file (owner bits for the owner, group bits for a member of the file's group, and other bits for everyone else), and ACL entries. ACL entries are read through getfacl when that tool is available; when it is not, the tool prints a plain line saying no ACL entries were read and the result rests on the mode bits. There is no acl library dependency. - Focused on Tools for analyzing and assessing file system permissions

The user defaults to the current user, resolved when the program runs and only when -u is not given, so --help works on machines without a login session. A named user who cannot be resolved exits 1 before any calculation.

## Install
`git clone https://github.com/ShadowGuard-AI/pa-effective-permission-calculator`
`pip install -r requirements.txt`

## Usage
`python3 main.py [-u USER] [-p PATH]`

## Parameters
- `-h`: Show help message and exit
- `-u, --user`: The username to check permissions for (default: the current user, resolved at run time only when -u is not given)
- `-p, --path`: The path to the file or directory (default: `.`, the current directory)

## Verified behavior
- `python3 -m py_compile main.py` passes, but `python3 main.py --help` fails in this sandbox at import: `rich` is not installed, and installs are forbidden in this wave. The parameter list above is taken from the argument parser in `main.py`, and no live calculation is claimed here. A live run also needs `getfacl` for ACL entries; without it, the result rests on the mode bits, as the opening states.
- Exit 1 cases, read from the code: a named user who cannot be resolved, and a path that does not exist.

## License
See LICENSE.
