from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.core.exceptions import AzureError
from config import Config
import logging
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
import subprocess
import json
import os
import platform

def get_azure_cli_path():
    if platform.system() == 'Windows':
        return r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
    else:
        return "az"  # On Linux, 'az' should be in the system PATH

def check_azure_authentication():
    az_cli_path = get_azure_cli_path()
    try:
        result = subprocess.run([az_cli_path, 'account', 'show'], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(result.stderr)
        account_info = json.loads(result.stdout)
        print("Successfully authenticated with Azure.")
        return {
            'status': 'Authenticated',
            'details': account_info
        }
    except Exception as e:
        print(f"Error checking Azure authentication: {e}")
        print(f"Azure CLI command output: {result.stderr if 'result' in locals() else 'No output'}")
        return {'status': 'Not Authenticated', 'details': str(e)}


def get_azure_credentials():
    return DefaultAzureCredential()

def get_compute_client():
    credentials = get_azure_credentials()
    return ComputeManagementClient(credentials, Config.AZURE_SUBSCRIPTION_ID)

def safe_get(obj, *keys):
    for key in keys:
        try:
            obj = obj[key] if isinstance(obj, dict) else getattr(obj, key)
        except (KeyError, AttributeError):
            return None
    return obj

def check_azure_cli_installed():
    az_cli_path = get_azure_cli_path()
    try:
        subprocess.run([az_cli_path, '--version'], check=True, capture_output=True, text=True)
        print("Azure CLI is installed.")
    except subprocess.CalledProcessError as e:
        print("Azure CLI is not installed or not found in PATH.")
        raise RuntimeError("Azure CLI is not installed or not found in PATH.") from e
