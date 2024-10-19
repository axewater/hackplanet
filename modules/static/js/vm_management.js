function performAction(action) {
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const loading = document.getElementById('loading');
    const result = document.getElementById('result');

    function disableButtons() {
        startBtn.disabled = true;
        stopBtn.disabled = true;
        
    }

    function enableButtons() {
        startBtn.disabled = false;
        stopBtn.disabled = false;
        
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
            action: action,
            lab_id: labId,
            vpn_server_name: vpnServerName
        })
    })
    .then(response => response.json())
    .then(data => {
        loading.style.display = 'none';
        if (data.status === "success") {
            result.textContent = data.message;
            updateStatusDisplay(action === 'start');
            }
        else {
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
