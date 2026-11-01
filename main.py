#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import grp
import pwd
import shutil
import stat
import subprocess
from rich.console import Console
from rich.table import Column, Table

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants ---
DEFAULT_PATH = "."  # Current directory


def resolve_default_user() -> str:
    """Returns the current user's login name, resolved lazily at run time."""
    try:
        return os.getlogin()
    except OSError:
        return pwd.getpwuid(os.getuid()).pw_name

# --- Helper Functions ---

def get_user_groups(user: str) -> list:
    """
    Retrieves a list of group names a user belongs to.

    Args:
        user: The username to check.

    Returns:
        A list of group names the user is a member of.  Returns an empty list if the user does not exist.
        Raises OSError or KeyError if the user or system groups cannot be accessed.
    """
    try:
        import pwd  # Import pwd inside the try block because its an optional system library
        user_info = pwd.getpwnam(user)
        group_list = [grp.getgrgid(g).gr_name for g in os.getgrouplist(user, user_info.pw_gid)]
        return group_list
    except KeyError:
        logging.error(f"User '{user}' not found.")
        return []
    except OSError as e:
        logging.error(f"Error retrieving group list for user '{user}': {e}")
        return []

def get_file_acl(path: str) -> list:
    """
    Retrieves the ACL entries for a given file or directory by reading the
    output of getfacl when that tool is available.

    Args:
        path: The path to the file or directory.

    Returns:
        A list of ACL entries. Returns an empty list if getfacl is not
        available or the file does not exist. Each entry is a dictionary
        with keys 'type', 'id', and 'permissions'.
    """
    getfacl = shutil.which("getfacl")
    if getfacl is None:
        logging.info("getfacl is not available; no ACL entries were read.")
        return []
    try:
        result = subprocess.run(
            [getfacl, "--absolute-names", path],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        logging.error(f"File or directory not found: {path}")
        return []
    except OSError as e:
        logging.error(f"Error retrieving ACL for {path}: {e}")
        return []

    owner = None
    owning_group = None
    raw_entries = []
    mask_perms = None
    for line in result.stdout.splitlines():
        if line.startswith("# owner:"):
            owner = line.split(":", 1)[1].strip()
            continue
        if line.startswith("# group:"):
            owning_group = line.split(":", 1)[1].strip()
            continue
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        entity_type, entity, perms = parts[0], parts[1], parts[2]
        if entity_type == "mask":
            mask_perms = perms
        else:
            raw_entries.append((entity_type, entity, perms))

    def to_permissions(perms, apply_mask):
        if apply_mask and mask_perms is not None:
            perms = "".join(c for c in perms if c in mask_perms)
        words = []
        if "r" in perms:
            words.append("read")
        if "w" in perms:
            words.append("write")
        if "x" in perms:
            words.append("execute")
        return words

    entries = []
    for entity_type, entity, perms in raw_entries:
        if entity_type == "user" and entity == "":
            entries.append({"type": "user", "id": owner, "permissions": to_permissions(perms, False)})
        elif entity_type == "user":
            entries.append({"type": "user", "id": entity, "permissions": to_permissions(perms, True)})
        elif entity_type == "group" and entity == "":
            entries.append({"type": "group", "id": owning_group, "permissions": to_permissions(perms, True)})
        elif entity_type == "group":
            entries.append({"type": "group", "id": entity, "permissions": to_permissions(perms, True)})
    return entries

def calculate_effective_permissions(user: str, path: str) -> dict:
    """
    Calculates the effective permissions a user has on a resource, considering group memberships,
    inherited permissions, and explicit denials.

    Args:
        user: The username to check.
        path: The path to the resource.

    Returns:
        A dictionary representing the effective permissions, with keys like 'read', 'write', and 'execute'.
    """
    effective_permissions = {'read': False, 'write': False, 'execute': False}
    user_groups = get_user_groups(user)
    acl_entries = get_file_acl(path)

    # Apply the file mode bits that match the user's relation to the file:
    # owner bits for the owner, group bits for a member of the file's group,
    # and other bits for everyone else.
    try:
        file_stat = os.stat(path)
        owner_username = pwd.getpwuid(file_stat.st_uid).pw_name
        file_group = grp.getgrgid(file_stat.st_gid).gr_name
        mode = file_stat.st_mode
        if owner_username == user:
            read_bit, write_bit, exec_bit = stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR
        elif file_group in user_groups:
            read_bit, write_bit, exec_bit = stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP
        else:
            read_bit, write_bit, exec_bit = stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH
        effective_permissions['read'] = effective_permissions['read'] or bool(mode & read_bit)
        effective_permissions['write'] = effective_permissions['write'] or bool(mode & write_bit)
        effective_permissions['execute'] = effective_permissions['execute'] or bool(mode & exec_bit)
    except (FileNotFoundError, OSError, KeyError) as e:
        logging.warning(f"Could not determine mode permissions for {path}: {e}")

    # Check ACL entries
    for entry in acl_entries:
        if entry['type'] == 'user' and entry['id'] == user:
            effective_permissions['read'] = effective_permissions['read'] or ('read' in entry['permissions'])
            effective_permissions['write'] = effective_permissions['write'] or ('write' in entry['permissions'])
            effective_permissions['execute'] = effective_permissions['execute'] or ('execute' in entry['permissions'])
        elif entry['type'] == 'group' and entry['id'] in user_groups:
            effective_permissions['read'] = effective_permissions['read'] or ('read' in entry['permissions'])
            effective_permissions['write'] = effective_permissions['write'] or ('write' in entry['permissions'])
            effective_permissions['execute'] = effective_permissions['execute'] or ('execute' in entry['permissions'])

        # Handle explicit denials (more complex logic may be needed for real ACLs)
        if entry['type'] == 'user' and entry['id'] == user and 'deny' in entry and entry['deny']:
            if 'read' in entry['permissions']:
                effective_permissions['read'] = False
            if 'write' in entry['permissions']:
                effective_permissions['write'] = False
            if 'execute' in entry['permissions']:
                effective_permissions['execute'] = False
        elif entry['type'] == 'group' and entry['id'] in user_groups and 'deny' in entry and entry['deny']:
            if 'read' in entry['permissions']:
                effective_permissions['read'] = False
            if 'write' in entry['permissions']:
                effective_permissions['write'] = False
            if 'execute' in entry['permissions']:
                effective_permissions['execute'] = False
    return effective_permissions

def display_permissions(user: str, path: str, permissions: dict):
    """
    Displays the calculated permissions in a user-friendly format using Rich.

    Args:
        user: The username being checked.
        path: The path to the resource.
        permissions: A dictionary of effective permissions.
    """
    console = Console()
    table = Table(title=f"Effective Permissions for [bold]{user}[/bold] on [bold]{path}[/bold]")

    table.add_column("Permission", style="cyan", justify="center")
    table.add_column("Status", style="magenta", justify="center")

    table.add_row("Read", "[green]Yes[/green]" if permissions['read'] else "[red]No[/red]")
    table.add_row("Write", "[green]Yes[/green]" if permissions['write'] else "[red]No[/red]")
    table.add_row("Execute", "[green]Yes[/green]" if permissions['execute'] else "[red]No[/red]")

    console.print(table)

# --- CLI Argument Parsing ---
def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        An argparse.ArgumentParser object.
    """
    parser = argparse.ArgumentParser(description="Calculates effective permissions for a user on a given resource.")
    parser.add_argument("-u", "--user", type=str, default=None, help="The username to check permissions for (default: the current user)")
    parser.add_argument("-p", "--path", type=str, default=DEFAULT_PATH, help=f"The path to the file or directory (default: {DEFAULT_PATH})")
    return parser

# --- Main Function ---
def main():
    """
    Main function to parse arguments, calculate permissions, and display the results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    user = args.user if args.user is not None else resolve_default_user()
    path = args.path

    try:
        pwd.getpwnam(user)
    except KeyError:
        logging.error(f"Error: User '{user}' could not be resolved.")
        sys.exit(1)

    # Input validation
    if not os.path.exists(path):
        logging.error(f"Error: Path '{path}' does not exist.")
        sys.exit(1)

    if not isinstance(user, str):
        logging.error("Error: User must be a string.")
        sys.exit(1)

    if not isinstance(path, str):
        logging.error("Error: Path must be a string.")
        sys.exit(1)

    try:
        permissions = calculate_effective_permissions(user, path)
        display_permissions(user, path, permissions)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()