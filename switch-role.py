#!/usr/bin/env python3
"""
AWS Role Assumption Script

This script reads account information from a text file and allows
assuming different AWS roles based on the information provided.
Default source account is 540625458825.
"""

import argparse
import boto3
import configparser
import json
import os
import sys
import re
from pathlib import Path


class AWSRoleAssumer:
    def __init__(self, config_file, source_account_id="540625458825"):
        """Initialize the role assumer with the given config file."""
        self.config_file = config_file
        self.source_account_id = source_account_id
        self.accounts = self._parse_config_file()
        self.mfa_serial = None
        
    def _parse_config_file(self):
        """Parse the configuration file and return a dictionary of accounts."""
        accounts = {}
        
        try:
            with open(self.config_file, 'r') as file:
                for line in file:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split(',')
                    if len(parts) < 5:
                        print(f"Warning: Skipping invalid line: {line}")
                        continue
                    
                    account_name = parts[1]
                    account_id = parts[2]
                    roles = parts[3].split(':')
                    region = parts[4]
                    output_format = parts[5] if len(parts) > 5 else 'json'
                    
                    accounts[account_name] = {
                        'id': account_id,
                        'roles': roles,
                        'region': region,
                        'output_format': output_format,
                        'short_code': parts[0]  # Added short code storage
                    }
        except FileNotFoundError:
            print(f"Error: Config file '{self.config_file}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"Error parsing config file: {e}")
            sys.exit(1)
            
        return accounts
    
    def list_accounts(self):
        """List all available accounts and their roles."""
        if not self.accounts:
            print("No accounts found in the configuration file.")
            return
        
        print("\nAvailable Accounts and Roles:")
        print("-----------------------------")
        for account_name, details in self.accounts.items():
            print(f"Account: {account_name} ({details['id']}) [Short code: {details['short_code']}]")
            print(f"  Region: {details['region']}")
            print(f"  Available Roles:")
            for role in details['roles']:
                print(f"    - {role}")
            print()

    def _check_and_get_mfa(self, session):
        """Check for MFA device and get MFA token if needed."""
        try:
            # Get current identity
            sts_client = session.client('sts')
            current_identity = sts_client.get_caller_identity()
            current_arn = current_identity['Arn']
            current_account_id = current_identity['Account']
            
            # Extract username from ARN: arn:aws:iam::123456789012:user/username
            if 'user/' in current_arn:
                username = current_arn.split('user/')[1]
                self.mfa_serial = f"arn:aws:iam::{current_account_id}:mfa/{username}"
                
                # Check if the MFA device exists
                try:
                    iam_client = session.client('iam')
                    response = iam_client.list_mfa_devices(UserName=username)
                    
                    if response['MFADevices']:
                        # Use the actual MFA serial if available
                        self.mfa_serial = response['MFADevices'][0]['SerialNumber']
                        
                        # Prompt for MFA token
                        print(f"MFA device detected: {self.mfa_serial}")
                        mfa_token = input("Enter MFA token code: ")
                        if not mfa_token or not mfa_token.isdigit() or len(mfa_token) != 6:
                            print("Invalid MFA token. MFA token should be a 6-digit number.")
                            return None
                        return mfa_token
                    else:
                        self.mfa_serial = None
                except Exception as e:
                    print(f"Unable to check MFA devices: {e}")
                    self.mfa_serial = None
            
            return None
        except Exception as e:
            print(f"Error checking MFA: {e}")
            return None
    
    def find_account_by_id_or_code(self, identifier):
        """Find an account by its ID or short code."""
        for account_name, details in self.accounts.items():
            if details['id'] == identifier or details['short_code'] == identifier:
                return account_name
        return None
        
    def assume_role(self, account_name, role_name, session_name=None):
        """Assume the specified role in the specified account."""
        # Check if account_name is an ID or short code and convert it to account name
        found_account = self.find_account_by_id_or_code(account_name)
        if found_account:
            account_name = found_account
            
        if account_name not in self.accounts:
            print(f"Error: Account '{account_name}' not found")
            return False
        
        account = self.accounts[account_name]
        if role_name not in account['roles']:
            print(f"Error: Role '{role_name}' not found for account '{account_name}'")
            print(f"Available roles: {', '.join(account['roles'])}")
            return False
        
        session_name = session_name or f"AssumeRoleSession-{os.getenv('USERNAME', 'user')}"
        
        try:
            # Get the current AWS credentials
            session = boto3.Session()
            sts_client = session.client('sts')
            
            # Get current identity to verify we're using the correct source account
            current_identity = sts_client.get_caller_identity()
            current_account_id = current_identity['Account']
            
            print(f"Current account: {current_account_id}")
            if current_account_id != self.source_account_id:
                print(f"Warning: You are not currently in the default source account ({self.source_account_id})")
                proceed = input("Do you want to proceed anyway? (y/n): ")
                if proceed.lower() != 'y':
                    print("Operation cancelled.")
                    return False
            
            # Check for MFA and get token if needed
            mfa_token = self._check_and_get_mfa(session)
            
            # Construct the role ARN
            role_arn = f"arn:aws:iam::{account['id']}:role/{role_name}"
            
            print(f"Assuming role: {role_arn}")
            
            # Call assume_role with or without MFA token
            if self.mfa_serial and mfa_token:
                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=session_name,
                    SerialNumber=self.mfa_serial,
                    TokenCode=mfa_token
                )
            else:
                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=session_name
                )
            
            # Set up credentials in environment variables
            credentials = assumed_role['Credentials']
            os.environ['AWS_ACCESS_KEY_ID'] = credentials['AccessKeyId']
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials['SecretAccessKey']
            os.environ['AWS_SESSION_TOKEN'] = credentials['SessionToken']
            os.environ['AWS_DEFAULT_REGION'] = account['region']
            os.environ['AWS_DEFAULT_OUTPUT'] = account['output_format']
            
            # Also save to credentials file for persistent use
            self._update_aws_credentials(
                credentials['AccessKeyId'],
                credentials['SecretAccessKey'],
                credentials['SessionToken'],
                account['region'],
                account['output_format'],
                f"{account_name}-{role_name}"
            )
            
            expiration = credentials['Expiration'].strftime('%Y-%m-%d %H:%M:%S')
            print(f"Role assumed successfully. Credentials will expire at: {expiration}")
            print(f"AWS credentials saved to profile: {account_name}-{role_name}")
            print(f"Environment variables set for current session.")
            
            # Display identity information
            new_session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=account['region']
            )
            
            sts = new_session.client('sts')
            identity = sts.get_caller_identity()
            print("\nNew identity:")
            print(f"Account: {identity['Account']}")
            print(f"UserId: {identity['UserId']}")
            print(f"ARN: {identity['Arn']}")
            
            return True
            
        except Exception as e:
            print(f"Error assuming role: {e}")
            return False
    
    def interactive_selection(self):
        """Interactive account and role selection."""
        if not self.accounts:
            print("No accounts found in the configuration file.")
            return False
            
        # Display accounts with numbers for selection
        print("\nAvailable Accounts:")
        print("-----------------")
        
        accounts_list = list(self.accounts.items())
        for i, (account_name, details) in enumerate(accounts_list, 1):
            print(f"{i}. {account_name} ({details['id']}) [Short code: {details['short_code']}]")
        
        # Get account selection
        try:
            selection = input("\nEnter account number, account ID, or short code: ")
            selected_account = None
            
            # Check if selection is a number (index)
            if selection.isdigit():
                index = int(selection) - 1
                if 0 <= index < len(accounts_list):
                    selected_account = accounts_list[index][0]
                else:
                    print("Invalid selection number.")
                    return False
            else:
                # Check if selection is an account ID or short code
                selected_account = self.find_account_by_id_or_code(selection)
                if not selected_account:
                    # Check if selection is an account name
                    if selection in self.accounts:
                        selected_account = selection
                    else:
                        print(f"Account with ID/short code/name '{selection}' not found.")
                        return False
            
            account = self.accounts[selected_account]
            print(f"\nSelected account: {selected_account} ({account['id']})")
            
            # Display roles with numbers for selection
            print("\nAvailable Roles:")
            print("---------------")
            roles = account['roles']
            for i, role in enumerate(roles, 1):
                print(f"{i}. {role}")
            
            # Get role selection
            role_selection = input("\nEnter role number or name: ")
            selected_role = None
            
            if role_selection.isdigit():
                index = int(role_selection) - 1
                if 0 <= index < len(roles):
                    selected_role = roles[index]
                else:
                    print("Invalid role number.")
                    return False
            else:
                if role_selection in roles:
                    selected_role = role_selection
                else:
                    print(f"Role '{role_selection}' not found.")
                    return False
            
            print(f"\nSelected role: {selected_role}")
            return self.assume_role(selected_account, selected_role)
            
        except Exception as e:
            print(f"Error during interactive selection: {e}")
            return False
    
    def _update_aws_credentials(self, access_key, secret_key, session_token, region, output_format, profile_name):
        """Update the AWS credentials file with the new temporary credentials."""
        credentials_file = os.path.join(str(Path.home()), '.aws', 'credentials')
        config_file = os.path.join(str(Path.home()), '.aws', 'config')
        
        # Ensure .aws directory exists
        os.makedirs(os.path.dirname(credentials_file), exist_ok=True)
        
        # Update credentials file
        credentials = configparser.ConfigParser()
        if os.path.exists(credentials_file):
            credentials.read(credentials_file)
        
        if not credentials.has_section(profile_name):
            credentials.add_section(profile_name)
        
        credentials[profile_name]['aws_access_key_id'] = access_key
        credentials[profile_name]['aws_secret_access_key'] = secret_key
        credentials[profile_name]['aws_session_token'] = session_token
        
        with open(credentials_file, 'w') as f:
            credentials.write(f)
        
        # Update config file
        config = configparser.ConfigParser()
        if os.path.exists(config_file):
            config.read(config_file)
        
        profile_section = f"profile {profile_name}"
        if not config.has_section(profile_section):
            config.add_section(profile_section)
        
        config[profile_section]['region'] = region
        config[profile_section]['output'] = output_format
        
        with open(config_file, 'w') as f:
            config.write(f)


def main():
    """Main function to parse arguments and execute commands."""
    parser = argparse.ArgumentParser(description="AWS Role Assumption Tool")
    parser.add_argument("--config", "-c", default="accounts.txt",
                        help="Path to the accounts configuration file (default: accounts.txt)")
    parser.add_argument("--source-account", "-s", default="540625458825",
                        help="Source AWS account ID (default: 540625458825)")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # List accounts command
    list_parser = subparsers.add_parser("list", help="List available accounts and roles")
    
    # Assume role command
    assume_parser = subparsers.add_parser("assume", help="Assume a role in an account")
    assume_parser.add_argument("account", help="Name, ID, or short code of the account to use")
    assume_parser.add_argument("role", help="Name of the role to assume")
    assume_parser.add_argument("--session-name", help="Custom session name (default: AssumeRoleSession-<username>)")
    
    # Interactive command
    interactive_parser = subparsers.add_parser("interactive", help="Interactively select account and role")
    
    args = parser.parse_args()
    
    # Initialize the role assumer
    assumer = AWSRoleAssumer(args.config, args.source_account)
    
    if args.command == "list":
        assumer.list_accounts()
    elif args.command == "assume":
        assumer.assume_role(args.account, args.role, args.session_name)
    elif args.command == "interactive":
        assumer.interactive_selection()
    else:
        # If no command is provided, default to interactive mode
        print("No command specified, starting interactive mode...")
        assumer.interactive_selection()


if __name__ == "__main__":
    main()
