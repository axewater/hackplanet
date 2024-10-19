var loops = 0;

document.addEventListener('DOMContentLoaded', function() {
    function updateHostStatus() {
        console.log('Fetching host status...');
        fetch('/api/host_status')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Network response was not ok: ${response.statusText}`);
                }
                return response.json();
            })
            .then(data => {
                console.log('Received host status data:', data);
                if (data.hosts) {
                    data.hosts.forEach(host => {
                        console.log(`Processing host_id: ${host.agent_id}, Status: ${host.status}, Is VPN: ${host.is_vpn}`);
                        const selector = host.is_vpn ? `.vpn-status-indicator[data-agent-id="${host.agent_id}"]` : `.status-indicator[data-agent-id="${host.agent_id}"]`;
                        const statusElement = document.querySelector(selector);
                        if (statusElement) {
                            let status = host.status;
                            let color;
                            switch (status) {
                                case 'Online':
                                    color = '#28a745';
                                    break;
                                case 'Offline':
                                    color = '#dc3545';
                                    break;
                                case 'Unknown':
                                    color = '#ffc107';
                                    break;
                                default:
                                    status = 'Unknown';
                                    color = '#ffc107';
                            }
                            statusElement.textContent = status;
                            statusElement.style.color = color;
                            console.log(`Updated status for agent_id: ${host.agent_id} to ${status}`);
                            
                            // Update VPN status in the lab section if it's a VPN server
                            if (host.is_vpn) {
                                const labVpnStatus = document.querySelector(`.lab-vpn-status[data-lab-id="${host.lab_id}"]`);
                                if (labVpnStatus) {
                                    labVpnStatus.textContent = status;
                                    labVpnStatus.style.color = color;
                                }
                            }
                        } else {
                            console.warn(`No status element found for agent_id: ${host.agent_id}`);
                        }
                    });
                } else {
                    console.error('No hosts data found in the response.');
                }
            })
            .catch(error => {
                console.error('Error fetching host status:', error);
            });
        }
    
        // Update status immediately and then every 30 seconds
        loops++;
        console.log(`Loop number: ${loops}`);
        updateHostStatus();
        setInterval(updateHostStatus, 30000);
    
        // VPN control functionality
        function manageVPN(labId, action) {
            fetch('/manage_vpn', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                },
                body: JSON.stringify({ lab_id: labId, action: action })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === "success") {
                    console.log(data.message);
                    updateHostStatus(); // Update status after VPN action
                } else {
                    console.error("Error managing VPN:", data.message);
                }
            })
            .catch(error => console.error('Error:', error));
        }
    
        document.addEventListener('click', function(event) {
            if (event.target.classList.contains('start-vpn')) {
                manageVPN(event.target.dataset.labId, 'start');
            } else if (event.target.classList.contains('stop-vpn')) {
                manageVPN(event.target.dataset.labId, 'stop');
            }
        });
    });
