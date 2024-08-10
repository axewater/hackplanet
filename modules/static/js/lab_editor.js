document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('lab-form');
    const feedbackMessage = document.getElementById('feedback-message');

    // Populate form fields if editing an existing lab
    if (window.location.pathname.includes('/lab_editor/')) {
        const labId = window.location.pathname.split('/').pop();
        fetch(`/admin/get_lab/${labId}`)
            .then(response => response.json())
            .then(data => {
                Object.keys(data).forEach(key => {
                    const field = form.elements[key];
                    if (field) {
                        field.value = data[key];
                    }
                });
            })
            .catch(error => {
                console.error('Error:', error);
                feedbackMessage.innerHTML = '<div class="alert alert-danger">Error loading lab data. Please try again.</div>';
            });
    }

    form.addEventListener('submit', function(event) {
        event.preventDefault();

        // Clear previous error messages
        document.querySelectorAll('.invalid-feedback').forEach(el => el.textContent = '');
        document.querySelectorAll('.form-control').forEach(el => el.classList.remove('is-invalid'));

        const formData = new FormData(form);
        const jsonData = {};
        formData.forEach((value, key) => {
            jsonData[key] = value;
        });

        // Log JSON data to console before submission
        console.log('JSON data to be submitted:', jsonData);

        fetch(form.action, {
            method: 'POST',
            body: JSON.stringify(jsonData),
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('input[name="csrf_token"]').value
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                feedbackMessage.innerHTML = '<div class="alert alert-success">Lab saved successfully!</div>';
                setTimeout(() => {
                    window.location.href = "/admin/lab_manager";
                }, 2000);
            } else {
                if (data.errors) {
                    Object.entries(data.errors).forEach(([field, errors]) => {
                        const errorElement = document.getElementById(`${field}-error`);
                        const inputElement = document.getElementById(field);
                        if (errorElement && inputElement) {
                            errorElement.textContent = errors.join(', ');
                            inputElement.classList.add('is-invalid');
                        }
                    });
                }
                feedbackMessage.innerHTML = `<div class="alert alert-danger">${data.message}</div>`;
            }
        })
        .catch(error => {
            console.error('Error:', error);
            feedbackMessage.innerHTML = `<div class="alert alert-danger">${error.message || 'An error occurred. Please try again.'}</div>`;
        });
    });
});