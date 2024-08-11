document.addEventListener('DOMContentLoaded', function() {
    const editButtons = document.querySelectorAll('.edit-lab');
    const deleteButtons = document.querySelectorAll('.delete-lab');
    const addHostButtons = document.querySelectorAll('.btn-success');

    editButtons.forEach(button => {
        button.addEventListener('click', function() {
            const labId = this.dataset.labId;
            window.location.href = `/admin/lab_editor/${labId}`;
        });
    });

    deleteButtons.forEach(button => {
        button.addEventListener('click', function() {
            const labId = this.dataset.labId;
            if (confirm('Are you sure? Deleting this lab will also delete ALL the hosts associated with it!')) {
                const csrfToken = document.querySelector('input[name="csrf_token"]').value;
                fetch(`/admin/delete_lab/${labId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        this.closest('tr').remove();
                        alert(data.message || 'Lab deleted successfully');
                    } else {
                        alert(data.message || 'Failed to delete lab');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred while deleting the lab: ' + error.message);
                });
            }
        });
    });

    addHostButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            event.preventDefault();
            const labId = this.getAttribute('href').split('=')[1];
            window.location.href = `/admin/host_editor?lab_id=${labId}`;
        });
    });
});