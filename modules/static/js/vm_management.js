function performAction(action) {
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const statusBtn = document.getElementById('status-btn');
    const statusDisplay = document.getElementById('vpn-status');
    const loading = document.getElementById('loading');
    const result = document.getElementById('result');

    function disableButtons() {
        startBtn.disabled = true;
        stopBtn.disabled = true;
        statusBtn.disabled = true;
    }

    function enableButtons() {
        startBtn.disabled = false;
        stopBtn.disabled = false;
        statusBtn.disabled = false;
    }

    function updateStatusDisplay(status) {
        statusDisplay.textContent = status ? 'Online' : 'Offline';
        statusDisplay.className = status ? 'text-success' : 'text-danger';
    }

    disableButtons();
    loading.style.display = 'block';
    result.innerHTML = '';

    fetch('/manage_vpn', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({
            action: action
        })
    })
    .then(response => response.json())
    .then(data => {
        loading.style.display = 'none';
        if (data.status === "success") {
            if (action === "status") {
                result.textContent = data.message;
                const isRunning = data.message.toLowerCase().includes('vm running');
                updateStatusDisplay(isRunning);
            } else {
                result.textContent = data.message;
                updateStatusDisplay(action === 'start');
            }
        } else {
            result.textContent = "Error: " + data.message;
        }
        enableButtons();
    })
    .catch(error => {
        loading.style.display = 'none';
        result.textContent = "Error: " + error;
        enableButtons();
    });
}

function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}
