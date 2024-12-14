document.addEventListener('DOMContentLoaded', function() {
    let userTable = document.getElementById('userTableBody');
    let userModal = new bootstrap.Modal(document.getElementById('userModal'));
    let deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
    let currentUserId = null;

    // Load users on page load
    loadUsers();

    // Add event listeners
    document.getElementById('addUserBtn').addEventListener('click', () => {
        clearUserForm();
        document.getElementById('userModalLabel').textContent = 'Add New User';
        userModal.show();
    });

    document.getElementById('saveUserBtn').addEventListener('click', saveUser);
    document.getElementById('userSearch').addEventListener('input', debounce(searchUsers, 300));
    document.getElementById('confirmDeleteBtn').addEventListener('click', deleteUser);

    // Username availability check
    document.getElementById('username').addEventListener('input', debounce(checkUsername, 500));

    function loadUsers(searchTerm = '') {
        fetch(`/api/users?search=${encodeURIComponent(searchTerm)}`)
            .then(response => response.json())
            .then(users => {
                userTable.innerHTML = '';
                users.forEach(user => {
                    userTable.innerHTML += `
                        <tr>
                            <td><img src="${user.avatar || '/static/newstyle/avatar_default.jpg'}" class="avatar" alt="Avatar"></td>
                            <td>${user.name}</td>
                            <td>${user.email}</td>
                            <td>${user.role}</td>
                            <td>${user.state ? '<span class="badge bg-success">Active</span>' : '<span class="badge bg-danger">Inactive</span>'}</td>
                            <td>
                                <button class="btn btn-sm btn-primary edit-user" data-id="${user.id}">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-sm btn-danger delete-user" data-id="${user.id}">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>
                    `;
                });
                addTableEventListeners();
            });
    }

    function addTableEventListeners() {
        document.querySelectorAll('.edit-user').forEach(button => {
            button.addEventListener('click', (e) => {
                const userId = e.target.closest('button').dataset.id;
                editUser(userId);
            });
        });

        document.querySelectorAll('.delete-user').forEach(button => {
            button.addEventListener('click', (e) => {
                const userId = e.target.closest('button').dataset.id;
                currentUserId = userId;
                deleteModal.show();
            });
        });
    }

    function editUser(userId) {
        fetch(`/api/users/${userId}`)
            .then(response => response.json())
            .then(user => {
                document.getElementById('userId').value = userId;
                document.getElementById('username').value = user.name;
                document.getElementById('email').value = user.email;
                document.getElementById('about').value = user.about || '';
                document.getElementById('invite_quota').value = user.invite_quota || 0;
                document.getElementById('role').value = user.role;
                document.getElementById('status').value = user.state ? '1' : '0';
                document.getElementById('is_email_verified').value = user.is_email_verified ? '1' : '0';
                document.getElementById('password').value = '';  // Clear password field
                document.getElementById('userModalLabel').textContent = 'Edit User';
                userModal.show();
            });
    }

    function saveUser() {
        const userId = document.getElementById('userId').value;
        const userData = {
            name: document.getElementById('username').value,
            email: document.getElementById('email').value,
            password: document.getElementById('password').value,
            role: document.getElementById('role').value,
            state: document.getElementById('status').value === '1',
            is_email_verified: document.getElementById('is_email_verified').value === '1'
        };

        fetch(`/api/users/${userId || 'new'}`, {
            method: userId ? 'PUT' : 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
            },
            body: JSON.stringify(userData)
        })
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                userModal.hide();
                loadUsers();
                showToast('Success', result.message);
            } else {
                showToast('Error', result.message, 'error');
            }
        });
    }

    function deleteUser() {
        if (!currentUserId) return;

        fetch(`/api/users/${currentUserId}`, {
            method: 'DELETE',
            headers: {
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
            }
        })
        .then(response => response.json())
        .then(result => {
            deleteModal.hide();
            if (result.success) {
                loadUsers();
                showToast('Success', 'User deleted successfully');
            } else {
                showToast('Error', result.message, 'error');
            }
        });
    }

    function searchUsers(e) {
        loadUsers(e.target.value);
    }

    function checkUsername(e) {
        const username = e.target.value;
        if (!username) return;

        fetch('/api/check_username', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
            },
            body: JSON.stringify({ username })
        })
        .then(response => response.json())
        .then(data => {
            const resultDiv = document.getElementById('username-check-result');
            if (data.exists) {
                resultDiv.textContent = 'Username not available';
                resultDiv.style.color = 'red';
            } else {
                resultDiv.textContent = 'Username available';
                resultDiv.style.color = 'green';
            }
        });
    }

    function clearUserForm() {
        document.getElementById('userId').value = '';
        document.getElementById('username').value = '';
        document.getElementById('email').value = '';
        document.getElementById('role').value = 'user';
        document.getElementById('status').value = '1';
        document.getElementById('username-check-result').textContent = '';
    }

    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    function showToast(title, message, type = 'success') {
        // Implement your preferred toast notification here
        alert(`${title}: ${message}`);
    }
});
