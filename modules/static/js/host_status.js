document.addEventListener('DOMContentLoaded', function() {
    function updateHostStatus() {
        fetch('/api/host_status')
            .then(response => response.json())
            .then(data => {
                if (data.hosts) {
                    data.hosts.forEach(host => {
                        const statusElement = document.querySelector(`.status-indicator[data-agent-id="${host.agent_id}"]`);
                        if (statusElement) {
                            const status = host.status === 'Offline' ? 'Offline' : 'Online';
                            statusElement.textContent = status;
                            statusElement.style.color = status === 'Online' ? '#28a745' : '#dc3545';
                        }
                    });
                }
            })
            .catch(error => console.error('Error fetching host status:', error));
    }

    // Update status immediately and then every 30 seconds
    updateHostStatus();
    setInterval(updateHostStatus, 30000);
});
