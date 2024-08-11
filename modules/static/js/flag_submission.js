document.addEventListener('DOMContentLoaded', function() {
    // Function to submit a flag
    window.submitFlag = function(hostId, flagType) {
        const flagInput = document.getElementById(`${flagType}-flag-${hostId}`);
        const flag = flagInput.value.trim();

        if (!flag) {
            alert('Please enter a flag.');
            return;
        }

        fetch('/submit_flag', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({
                host_id: hostId,
                flag_type: flagType,
                flag: flag
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Flag submitted successfully!');
                flagInput.value = '';
            } else {
                alert(data.message || 'Failed to submit flag. Please try again.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred. Please try again.');
        });
    };

    // Function to get CSRF token
    function getCsrfToken() {
        return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    }
});
