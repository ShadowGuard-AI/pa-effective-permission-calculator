#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import grp
import acl
from rich.console import Console
from rich.table import Column, Table

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants ---
DEFAULT_USER = os.getlogin()  # Get the current user's login name
DEFAULT_PATH = "."  # Current directory

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
    Retrieves the ACL entries for a given file or directory.

    Args:
        path: The path to the file or directory.

    Returns:
        A list of ACL entries. Returns an empty list if there are no ACL entries or if the file does not exist.
        Each entry is a dictionary with keys like 'type', 'id', and 'permissions'.
    """
    try:
        acl_entries = acl.acl(file=path).get()
        return acl_entries
    except FileNotFoundError:
        logging.error(f"File or directory not found: {path}")
        return []
    except OSError as e:
        logging.error(f"Error retrieving ACL for {path}: {e}")
        return []

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

    # Check file owner permissions
    try:
        import stat
        file_stat = os.stat(path)
        owner_uid = file_stat.st_uid
        import pwd
        owner_username = pwd.getpwuid(owner_uid).pw_name
        if owner_username == user:
            mode = file_stat.st_mode
            effective_permissions['read'] = bool(mode & stat.S_IRUSR)
            effective_permissions['write'] = bool(mode & stat.S_IWUSR)
            effective_permissions['execute'] = bool(mode & stat.S_IXUSR)
    except (FileNotFoundError, OSError, ImportError, KeyError) as e:
        logging.warning(f"Could not determine owner permissions for {path}: {e}")

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
    parser.add_argument("-u", "--user", type=str, default=DEFAULT_USER, help=f"The username to check permissions for (default: {DEFAULT_USER})")
    parser.add_argument("-p", "--path", type=str, default=DEFAULT_PATH, help=f"The path to the file or directory (default: {DEFAULT_PATH})")
    return parser

# --- Main Function ---
def main():
    """
    Main function to parse arguments, calculate permissions, and display the results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    user = args.user
    path = args.path

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

# --- Offensive Tool Steps ---
# Include steps for offensive tools (simulated here - replace with actual offensive actions).
# This simulates actions an attacker might take after assessing permissions.

def simulate_offensive_actions(user: str, path: str, permissions: dict):
    """
    Simulates offensive actions based on calculated permissions.  This is a placeholder.
    Replace with actual offensive actions.
    """
    logging.info(f"Simulating offensive actions for user {user} on {path}:")
    if permissions['read']:
        logging.info(f"- User {user} can read {path}.")
        # Simulate reading the file content (replace with actual file reading)
        logging.info(f"  - Simulated: Reading content of {path}...")

    if permissions['write']:
        logging.info(f"- User {user} can write to {path}.")
        # Simulate writing to the file (replace with actual file writing)
        logging.info(f"  - Simulated: Attempting to modify {path}...")

    if permissions['execute']:
        logging.info(f"- User {user} can execute {path} (if it's an executable).")
        # Simulate executing the file (replace with actual execution)
        logging.info(f"  - Simulated: Executing {path}...")


if __name__ == "__main__":
    main()