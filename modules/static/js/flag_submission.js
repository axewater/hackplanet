document.addEventListener('DOMContentLoaded', function() {
    // Function to submit a flag
    window.submitFlag = function(hostId, flagType) {
        const flagInput = document.getElementById(`${flagType}-flag-${hostId}`);
        const flag = flagInput.value.trim();
        const submitButton = document.querySelector(`button[onclick="submitFlag('${hostId}', '${flagType}')"]`);

        if (!flag) {
            showModal('Error', 'Please enter a flag.');
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
                showModal('🎉 Success', 'Flag submitted successfully! 🚩');
                flagInput.value = '';
                submitButton.disabled = true;
                submitButton.textContent = 'Completed';
                
                // Remove the input field
                flagInput.style.display = 'none';
                
                // Check if both flags are completed
                const otherFlagType = flagType === 'user' ? 'root' : 'user';
                const otherSubmitButton = document.querySelector(`button[onclick="submitFlag('${hostId}', '${otherFlagType}')"]`);
                const otherFlagInput = document.getElementById(`${otherFlagType}-flag-${hostId}`);
                if (otherSubmitButton && otherSubmitButton.disabled) {
                    showCompletedBanner(hostId);
                    // Remove the other input field if both flags are completed
                    otherFlagInput.style.display = 'none';
                }
            } else {
                showModal('⚠️ Error', data.message || 'Failed to submit flag. Please try again. 🔄');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showModal('Error', 'An error occurred. Please try again.');
        });
    };

    // Function to get CSRF token
    function getCsrfToken() {
        return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    }

    // Function to show modal
    function showModal(title, message) {
        const modal = document.getElementById('flagModal');
        const modalTitle = document.getElementById('flagModalLabel');
        const modalBody = document.getElementById('flagModalBody');
        
        modalTitle.textContent = title;
        modalBody.textContent = message;
        
        const bootstrapModal = new bootstrap.Modal(modal);
        bootstrapModal.show();
    }



    // Check for completed flags on page load
    document.querySelectorAll('.host').forEach(host => {
        const hostId = host.dataset.hostId;
        const userButton = host.querySelector(`button[onclick="submitFlag('${hostId}', 'user')"]`);
        const rootButton = host.querySelector(`button[onclick="submitFlag('${hostId}', 'root')"]`);

        if (userButton && rootButton && userButton.disabled && rootButton.disabled) {
            showCompletedOverlay(hostId);
        }
    });
});
