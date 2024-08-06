from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from config import Config

def get_azure_credentials():
    return DefaultAzureCredential()

def get_compute_client():
    credentials = get_azure_credentials()
    return ComputeManagementClient(credentials, Config.AZURE_SUBSCRIPTION_ID)

def get_vm_status(vm_id):
    compute_client = get_compute_client()
    resource_group_name, vm_name = vm_id.split('/')[-4], vm_id.split('/')[-1]
    vm = compute_client.virtual_machines.get(resource_group_name, vm_name, expand='instanceView')
    status = next((s.display_status for s in vm.instance_view.statuses if s.code.startswith('PowerState/')), None)
    return status

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
