document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    const nameError = document.getElementById('name-error');
    const imageError = document.getElementById('image-error');
    const descriptionError = document.getElementById('description-error');

    form.addEventListener('submit', function(event) {
        event.preventDefault();

        const formData = new FormData(form);

        fetch(form.action, {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Redirect to the lab manager page
                window.location.href = data.redirect;
            } else {
                // Display validation errors
                nameError.textContent = data.errors.name || '';
                imageError.textContent = data.errors.image || '';
                descriptionError.textContent = data.errors.description || '';
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });
});