from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.core.exceptions import AzureError
from config import Config
import logging

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

def start_vm(vm_id):
    compute_client = get_compute_client()
    resource_group_name, vm_name = vm_id.split('/')[-4], vm_id.split('/')[-1]
    async_vm_start = compute_client.virtual_machines.begin_start(resource_group_name, vm_name)
    async_vm_start.wait()

def stop_vm(vm_id):
    compute_client = get_compute_client()
    resource_group_name, vm_name = vm_id.split('/')[-4], vm_id.split('/')[-1]
    async_vm_stop = compute_client.virtual_machines.begin_power_off(resource_group_name, vm_name)
    async_vm_stop.wait()

def restart_vm(vm_id):
    compute_client = get_compute_client()
    resource_group_name, vm_name = vm_id.split('/')[-4], vm_id.split('/')[-1]
    async_vm_restart = compute_client.virtual_machines.begin_restart(resource_group_name, vm_name)
    async_vm_restart.wait()
