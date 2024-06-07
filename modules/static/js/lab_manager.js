document.addEventListener('DOMContentLoaded', function() {
    const editButtons = document.querySelectorAll('.edit-lab');
    const deleteButtons = document.querySelectorAll('.delete-lab');

    editButtons.forEach(button => {
        button.addEventListener('click', function() {
            const labId = this.dataset.labId;
            // Send AJAX request to edit the lab
            // Update the UI with the response
        });
    });

    deleteButtons.forEach(button => {
        button.addEventListener('click', function() {
            const labId = this.dataset.labId;
            // Send AJAX request to delete the lab
            // Update the UI with the response
        });
    });
});