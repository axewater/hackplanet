document.addEventListener('DOMContentLoaded', function() {
    const avatarSource = document.getElementsByName('avatar_source');
    const gallerySection = document.getElementById('gallerySection');
    const customSection = document.getElementById('customSection');
    const galleryItems = document.querySelectorAll('.gallery-item');
    const gallerySelect = document.getElementById('gallery_avatar');
    const saveButton = document.getElementById('saveProfile');
    const form = document.querySelector('form');

    // Add form submission handler
    saveButton.addEventListener('click', function(e) {
        e.preventDefault();
        form.submit();
    });

    function updateSections(value) {
        if (value === 'gallery') {
            gallerySection.style.display = 'block';
            customSection.style.display = 'none';
        } else {
            gallerySection.style.display = 'none';
            customSection.style.display = 'block';
        }
    }

    avatarSource.forEach(radio => {
        radio.addEventListener('change', (e) => {
            updateSections(e.target.value);
        });
    });

    galleryItems.forEach(item => {
        item.addEventListener('click', () => {
            const value = item.dataset.value;
            gallerySelect.value = value;
            galleryItems.forEach(i => i.classList.remove('selected'));
            item.classList.add('selected');
        });
    });

    updateSections(document.querySelector('input[name="avatar_source"]:checked').value);
});
