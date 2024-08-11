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

def get_vm_status(vm_id):
    logging.info(f"Attempting to retrieve VM status for VM ID: {vm_id}")
    try:
        compute_client = get_compute_client()
        resource_group_name, vm_name = vm_id.split('/')[-4], vm_id.split('/')[-1]
        logging.info(f"Fetching VM details for resource group: {resource_group_name}, VM name: {vm_name}")
        
        vm = compute_client.virtual_machines.get(resource_group_name, vm_name, expand='instanceView')
        logging.info(f"Full API response: {vm.as_dict()}")
        
        statuses = safe_get(vm, 'instance_view', 'statuses')
        if not statuses:
            logging.warning("No status information found in the VM instance view")
            return "Unknown"
        
        status = next((s.display_status for s in statuses if s.code.startswith('PowerState/')), None)
        if status:
            logging.info(f"VM status retrieved successfully: {status}")
        else:
            logging.warning("No power state status found in the VM instance view")
        return status or "Unknown"
    except AzureError as ae:
        logging.error(f"Azure-specific error occurred: {str(ae)}")
        return f"Azure Error: {str(ae)}"
    except Exception as e:
        logging.error(f"Unexpected error retrieving VM status: {str(e)}")
        return f"Unexpected Error: {str(e)}"


def check_azure_cli_installed():
    az_cli_path = get_azure_cli_path()
    try:
        subprocess.run([az_cli_path, '--version'], check=True, capture_output=True, text=True)
        print("Azure CLI is installed.")
    except subprocess.CalledProcessError as e:
        print("Azure CLI is not installed or not found in PATH.")
        raise RuntimeError("Azure CLI is not installed or not found in PATH.") from e
