var loops = 0;

document.addEventListener('DOMContentLoaded', function() {
    function updateHostStatus() {
        fetch('/api/host_status')
            .then(response => response.json())
            .then(data => {
                console.log('Host status data:', data);
                if (data.hosts) {
                    data.hosts.forEach(host => {
                        const statusElement = document.querySelector(`.status-indicator[data-agent-id="${host.agent_id}"]`);
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
                            if (status === 'Unknown') {
                                console.log(`Host ${host.agent_id} status is unknown`);
                            }
                        }
                    });
                }
            })
            .catch(error => console.error('Error fetching host status:', error));
    }

    // Update status immediately and then every 30 seconds
    loops++;
    console.log(`Loop number: ${loops}`);
    updateHostStatus();
    setInterval(updateHostStatus, 30000);
});
