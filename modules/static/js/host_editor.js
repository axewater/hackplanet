document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('host-form');
    const feedbackMessage = document.getElementById('feedback-message');

    form.addEventListener('submit', function(e) {
        e.preventDefault();

        const formData = new FormData(form);
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;

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
                    window.location.href = "{{ url_for('main.host_manager') }}";
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
