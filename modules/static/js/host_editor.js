document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('host-form');
    const feedbackMessage = document.getElementById('feedback-message');
    const labIdSelect = document.getElementById('lab_id');

    // Add event listener for lab_id changes
    labIdSelect.addEventListener('change', function() {
        console.log('Lab ID changed:', this.value);
        // Add this line to update a hidden input field with the selected lab_id
        document.getElementById('selected_lab_id').value = this.value;
    });

    // Add this function to log all form data
    function logFormData() {
        const formData = new FormData(form);
        console.log('Current form values:');
        for (let [key, value] of formData.entries()) {
            console.log(key + ':', value);
        }
    }

    // Log form data when the page loads
    logFormData();

    // Log form data when any input changes
    form.addEventListener('change', logFormData);

    form.addEventListener('submit', function(e) {
        e.preventDefault();

        const formData = new FormData(form);
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;

        // Log form values when submitting
        console.log('Submitting form with values:');
        logFormData();

        fetch(form.action, {
            method: 'POST',
            body: formData,
            headers: {
                'X-CSRFToken': csrfToken
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                feedbackMessage.innerHTML = '<div class="alert alert-success">Host saved successfully!</div>';
                setTimeout(() => {
                    window.location.href = "/admin/host_manager";
                }, 2000);
            } else {
                let errorHtml = '<div class="alert alert-danger">';
                errorHtml += `<p>${data.message}</p>`;
                if (data.errors) {
                    errorHtml += '<ul>';
                    for (const [field, errors] of Object.entries(data.errors)) {
                        for (const error of errors) {
                            errorHtml += `<li>${field}: ${error}</li>`;
                        }
                    }
                    errorHtml += '</ul>';
                }
                errorHtml += '</div>';
                feedbackMessage.innerHTML = errorHtml;
            }
        })
        .catch(error => {
            console.error('Error:', error);
            feedbackMessage.innerHTML = '<div class="alert alert-danger">An error occurred. Please try again.</div>';
        });
    });
});
