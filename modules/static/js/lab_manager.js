document.addEventListener('DOMContentLoaded', function() {
    const editButtons = document.querySelectorAll('.edit-lab');
    const deleteButtons = document.querySelectorAll('.delete-lab');

    editButtons.forEach(button => {
        button.addEventListener('click', function() {
            const labId = this.dataset.labId;
            window.location.href = `/admin/lab_editor/${labId}`;
        });
    });

    deleteButtons.forEach(button => {
        button.addEventListener('click', function() {
            const labId = this.dataset.labId;
            if (confirm('Are you sure you want to delete this lab?')) {
                fetch(`/admin/delete_lab/${labId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrf_token')
                    },
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        this.closest('tr').remove();
                    } else {
                        alert('Failed to delete lab');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred while deleting the lab');
                });
            }
        });
    });

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }
});