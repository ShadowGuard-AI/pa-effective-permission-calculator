# pa-effective-permission-calculator
Calculates the effective permissions a user has on a specific resource, taking into account group memberships, the file mode bits that match the user's relation to the file (owner bits for the owner, group bits for a member of the file's group, and other bits for everyone else), and ACL entries. ACL entries are read through getfacl when that tool is available; when it is not, the tool prints a plain line saying no ACL entries were read and the result rests on the mode bits. There is no acl library dependency. - Focused on Tools for analyzing and assessing file system permissions

The user defaults to the current user, resolved when the program runs and only when -u is not given, so --help works on machines without a login session. A named user who cannot be resolved exits 1 before any calculation.

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-effective-permission-calculator`

## Usage
`./pa-effective-permission-calculator [params]`

## Parameters
- `-h`: Show help message and exit
- `-u`: No description provided
- `-p`: No description provided

## License
Copyright (c) ShadowStrikeHQ
