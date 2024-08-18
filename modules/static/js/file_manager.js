document.addEventListener('DOMContentLoaded', function() {
    let currentPath = '/';

    function loadFileList(path) {
        fetch(`/admin/media/list?path=${encodeURIComponent(path)}`)
            .then(response => response.json())
            .then(data => {
                const fileList = document.getElementById('fileList');
                fileList.innerHTML = '';
                
                // Sort the files: folders first, then files, both in alphabetical order
                data.files.sort((a, b) => {
                    if (a.is_dir && !b.is_dir) return -1;
                    if (!a.is_dir && b.is_dir) return 1;
                    return a.name.localeCompare(b.name);
                });
                
                data.files.forEach(file => {
                    const row = document.createElement('tr');
                    let fileContent = file.is_dir ? '<i class="fas fa-folder"></i> ' : '';
                    
                    if (!file.is_dir && file.type.startsWith('image/')) {
                        fileContent += `<img src="/admin/media/thumbnail?path=${encodeURIComponent(file.path)}" class="img-thumbnail" style="max-width: 50px; max-height: 50px;" /> `;
                    }
                    
                    fileContent += `<a href="#" class="file-link" data-path="${file.path}">${file.name}</a>`;
                    
                    row.innerHTML = `
                        <td>${fileContent}</td>
                        <td>${file.type}</td>
                        <td>${file.size}</td>
                        <td>
                            ${file.is_dir ? '' : '<button class="btn btn-sm btn-primary download-btn">Download</button>'}
                            <button class="btn btn-sm btn-danger delete-btn">Delete</button>
                        </td>
                    `;
                    fileList.appendChild(row);
                });
                updateBreadcrumb(path);
                updateUploadButton(path);
            });
    }

    function showFullImage(path) {
        const modal = new bootstrap.Modal(document.getElementById('imageViewerModal'));
        const modalImage = document.getElementById('fullSizeImage');
        modalImage.src = `/admin/media/download?path=${encodeURIComponent(path)}`;
        modal.show();
    }

    function updateUploadButton(path) {
        const uploadBtn = document.getElementById('uploadBtn');
        uploadBtn.disabled = path === '/';
    }

    function showFullImage(path) {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Full Image</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <img src="/admin/media/download?path=${encodeURIComponent(path)}" class="img-fluid" />
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        new bootstrap.Modal(modal).show();
    }

    function updateBreadcrumb(path) {
        const breadcrumb = document.getElementById('breadcrumb');
        const parts = path.split('/').filter(Boolean);
        let html = '<nav aria-label="breadcrumb"><ol class="breadcrumb"><li class="breadcrumb-item"><a href="#" data-path="/" class="breadcrumb-chip">Root</a></li>';
        let currentPath = '';
        parts.forEach((part, index) => {
            currentPath += '/' + part;
            html += '<li class="breadcrumb-item">';
            if (index === parts.length - 1) {
                html += `<span class="breadcrumb-chip">${part}</span>`;
            } else {
                html += `<a href="#" data-path="${currentPath}" class="breadcrumb-chip">${part}</a>`;
            }
            html += '</li>';
        });
        html += '</ol></nav>';
        breadcrumb.innerHTML = html;
    }

    document.getElementById('fileList').addEventListener('click', function(e) {
        if (e.target.classList.contains('file-link')) {
            e.preventDefault();
            const path = e.target.getAttribute('data-path');
            if (e.target.closest('td').querySelector('.fa-folder')) {
                currentPath = path;
                loadFileList(path);
            } else if (e.target.closest('td').querySelector('img')) {
                showFullImage(path);
            }
        } else if (e.target.tagName === 'IMG' && !e.target.closest('td').querySelector('.fa-folder')) {
            const path = e.target.closest('tr').querySelector('.file-link').getAttribute('data-path');
            showFullImage(path);
        } else if (e.target.classList.contains('download-btn')) {
            const path = e.target.closest('tr').querySelector('.file-link').getAttribute('data-path');
            window.location.href = `/admin/media/download?path=${encodeURIComponent(path)}`;
        } else if (e.target.classList.contains('delete-btn')) {
            const path = e.target.closest('tr').querySelector('.file-link').getAttribute('data-path');
            if (confirm('Are you sure you want to delete this item?')) {
                fetch('/admin/media/delete', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                    },
                    body: JSON.stringify({ path: path })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        loadFileList(currentPath);
                    } else {
                        alert('Error deleting item: ' + data.message);
                    }
                });
            }
        }
    });

    document.getElementById('breadcrumb').addEventListener('click', function(e) {
        if (e.target.tagName === 'A') {
            e.preventDefault();
            const path = e.target.getAttribute('data-path');
            currentPath = path;
            loadFileList(path);
        }
    });

    document.getElementById('uploadBtn').addEventListener('click', function() {
        $('#uploadModal').modal('show');
    });

    document.getElementById('submitUpload').addEventListener('click', function() {
        const formData = new FormData(document.getElementById('uploadForm'));
        formData.append('path', currentPath);
        fetch('/admin/media/upload', {
            method: 'POST',
            body: formData,
            headers: {
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                $('#uploadModal').modal('hide');
                loadFileList(currentPath);
                showAlert('success', 'File uploaded successfully');
            } else {
                showAlert('error', 'Error uploading file: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showAlert('error', 'An unexpected error occurred');
        });
    });

    function showAlert(type, message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        document.querySelector('.container').prepend(alertDiv);
        setTimeout(() => {
            alertDiv.remove();
        }, 5000);
    }

    document.getElementById('createFolderBtn').addEventListener('click', function() {
        $('#createFolderModal').modal('show');
    });

    document.getElementById('submitCreateFolder').addEventListener('click', function() {
        const folderName = document.getElementById('folderName').value;
        fetch('/admin/media/create_folder', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
            },
            body: JSON.stringify({ path: currentPath, name: folderName })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                $('#createFolderModal').modal('hide');
                loadFileList(currentPath);
            } else {
                alert('Error creating folder: ' + data.message);
            }
        });
    });

    loadFileList(currentPath);
});
