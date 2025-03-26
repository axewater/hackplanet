from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from modules import db
from modules.models import Host, Lab, SystemMessage
from modules.azure_utils import get_azure_cli_path
from config import Config
import subprocess, json
bp_vm = Blueprint('bp_vm', __name__)

@bp_vm.route('/manage_vm', methods=['POST'])
@login_required
def manage_vm():
    print(f"Received request to manage VM: {request.form}")
    resource_group = request.form['resource_group']
    vm_name = request.form['vm_name']
    action = request.form['action']
    subscription_id = Config.AZURE_SUBSCRIPTION_ID
    vm_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}"
    az_cli_path = get_azure_cli_path()
    try:
        output = ""
        if action == 'start':
            # Create system message for VM start
            message = SystemMessage(
                type='information',
                contents=f"User {current_user.name} booting up host {vm_name}"
            )
            db.session.add(message)
            db.session.commit()
            print(f"Executing VM start command for {vm_id}")
            result = subprocess.run([az_cli_path, 'vm', 'start', '--ids', vm_id], capture_output=True, text=True)
            if result.returncode == 0:
                host = Host.query.filter_by(azure_vm_id=vm_id).first()
                if host:
                    host.status = True
                    db.session.commit()
        elif action == 'stop':
            print(f"Executing VM stop command for {vm_id}")
            result = subprocess.run([az_cli_path, 'vm', 'stop', '--ids', vm_id], capture_output=True, text=True)
            if result.returncode == 0:
                # Create system message for VM stop
                message = SystemMessage(
                    type='information',
                    contents=f"User {current_user.name} shutdown host {vm_name}"
                )
                db.session.add(message)
                db.session.commit()
                host = Host.query.filter_by(azure_vm_id=vm_id).first()
                if host:
                    host.status = False
                    db.session.commit()
        else:
            print(f"Invalid action received: {action}")
            raise ValueError("Invalid action")
        if result.returncode != 0:
            raise Exception(f"Error performing {action} on VM: {result.stderr}")
        if not output:
            output = f"Successfully performed {action} on VM: {vm_id}"
        print(output)
        return jsonify({"status": "success", "message": output})
    except Exception as e:
        print(f"Detailed error while managing VM: {e}")
        print(f"Error managing VM: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400

@bp_vm.route('/manage_vpn', methods=['POST'])
@login_required
def manage_vpn():
    print(f"Received request to manage VPN: {request.json}")
    action = request.json['action']
    lab_id = request.json['lab_id']
    lab = Lab.query.get_or_404(lab_id)
    vpn_server_name = lab.vpn_server  # Use the lab's vpn_server field
    if not vpn_server_name:
        return jsonify({"status": "error", "message": "No VPN server associated with this lab"}), 400
    subscription_id = Config.AZURE_SUBSCRIPTION_ID
    resource_group = Config.AZURE_RESOURCE_GROUP
    vm_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vpn_server_name}"
    az_cli_path = get_azure_cli_path()
    
    try:
        output = ""
        if action == 'status':
            print(f"Executing VPN status command for{vm_id}")
            result = subprocess.run([az_cli_path, 'vm', 'get-instance-view', '--ids', vm_id, '--query', '{name:name, powerState:instanceView.statuses[1].displayStatus}'], capture_output=True, text=True)
            if result.returncode == 0:
                vm_info = json.loads(result.stdout)
                output = f"VPN Server: {vm_info['name']}, Power State: {vm_info['powerState']}"
            else:
                raise Exception(f"Error fetching VPN status: {result.stderr}")
        elif action == 'start':
            print(f"Executing VPN start command for {vm_id}")
            result = subprocess.run([az_cli_path, 'vm', 'start', '--ids', vm_id], capture_output=True, text=True)
            if result.returncode == 0:
                output = "VPN server started successfully"
            else:
                raise Exception(f"Error starting VPN: {result.stderr}")
        elif action == 'stop':
            print(f"Executing VPN stop command for {vm_id}")
            result = subprocess.run([az_cli_path, 'vm', 'stop', '--ids', vm_id], capture_output=True, text=True)
            if result.returncode == 0:
                output = "VPN server stopped successfully"
            else:
                raise Exception(f"Error stopping VPN: {result.stderr}")
        else:
            print(f"Invalid action received: {action}")
            raise ValueError("Invalid action")
        
        print(output)
        return jsonify({"status": "success", "message": output})
    except Exception as e:
        print(f"Detailed error while managing VPN: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400