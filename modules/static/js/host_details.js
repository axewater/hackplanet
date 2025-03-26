$(document).ready(function() {
    const hostId = $('#host_id').val();
    function getCsrfToken() {
        return $('input[name="csrf_token"]').val();
    }

    function disableButtons() {
        $('#start-btn, #stop-btn').prop('disabled', true);
    }

    function enableButtons() {
        $('#start-btn, #stop-btn').prop('disabled', false);
    }

    
    function performAction(action) {
        disableButtons();
        $('#loading').show();
        $('#result').html('');
        $.ajax({
            url: "/manage_vm",
            type: "POST",
            data: {
                resource_group: $('#resource_group').val(),
                vm_name: $('#vm_name').val(),
                action: action,
                csrf_token: getCsrfToken()
            },
            headers: {
                'X-CSRFToken': getCsrfToken()
            },
            success: function(response) {
                $('#loading').hide();
                if (response.status === "success") {
                    }
                else {
                    $('#result').html("<p>Error: " + response.message + "</p>");
                }
                enableButtons();
            },
            error: function(xhr, status, error) {
                $('#loading').hide();
                $('#result').html("<p>Error: " + error + "</p>");
                enableButtons();
            }
        });
    }

    $('#start-btn').click(function() { performAction('start'); });
    $('#stop-btn').click(function() { performAction('stop'); });
    
    $('#refresh-btn').click(function() { location.reload(); });
    
    // Star rating system
    initializeStarRatings();
    loadReviews();
    
    // Initialize star display for existing ratings
    function initializeStarRatings() {
        // For display-only stars
        $('.stars').each(function() {
            const rating = parseFloat($(this).data('rating')) || 0;
            $(this).empty();
            
            for (let i = 1; i <= 5; i++) {
                const star = $('<i class="fas fa-star"></i>');
                if (i <= rating) {
                    star.addClass('active');
                }
                $(this).append(star);
            }
        });
        
        // For interactive rating inputs
        $('.rating-input i').on('mouseover', function() {
            const value = $(this).data('value');
            const parent = $(this).parent();
            
            parent.find('i').removeClass('active hovered');
            parent.find('i').each(function() {
                if ($(this).data('value') <= value) {
                    $(this).addClass('hovered');
                }
            });
        }).on('mouseout', function() {
            $(this).parent().find('i').removeClass('hovered');
        });
        
        $('.rating-input').on('mouseout', function() {
            const parent = $(this).parent();
            const inputValue = parent.siblings('input[type="hidden"]').val();
            
            parent.find('i').removeClass('active');
            parent.find('i').each(function() {
                if ($(this).data('value') <= inputValue) {
                    $(this).addClass('active');
                }
            });
        });
        
        $('.rating-input i').on('click', function() {
            const value = $(this).data('value');
            const parent = $(this).parent();
            parent.find('i').removeClass('active');
            parent.find('i').each(function() {
                if ($(this).data('value') <= value) {
                    $(this).addClass('active');
                }
            });
            parent.siblings('input[type="hidden"]').val(value);
        });
        
        // Set default values for rating inputs
        setDefaultRatingValues(3);
    }
    
    function setDefaultRatingValues(value) {
        $('#difficulty_rating_input, #fun_rating_input, #realism_rating_input').val(value);
        $('.rating-input').each(function() {
            $(this).find('i').removeClass('active');
            $(this).find(`i[data-value="${value}"]`).prevAll().addBack().addClass('active');
        });
    }
    
    // Load existing reviews
    function loadReviews() {
        $.ajax({
            url: `/api/host/${hostId}/reviews`,
            type: 'GET',
            success: function(response) {
                if (response.success) {
                    displayReviews(response.reviews);
                }
            },
            error: function(xhr) {
                console.error('Error loading reviews:', xhr.responseText);
            }
        });
    }
    
    // Display reviews in the reviews container
    function displayReviews(reviews) {
        const container = $('#reviews-container');
        container.empty();
        
        if (reviews.length === 0) {
            container.append('<p>No reviews yet. Be the first to review this host!</p>');
            return;
        }
        
        const reviewsList = $('<div class="reviews-list"></div>');
        
        reviews.forEach(review => {
            const reviewElement = $(`
                <div class="review-item card mb-3">
                    <div class="card-body">
                        <h5 class="card-title">${review.user_name}</h5>
                        <div class="review-ratings">
                            <p><strong>Difficulty:</strong> <span class="stars" data-rating="${review.difficulty_rating}"></span></p>
                            <p><strong>Fun:</strong> <span class="stars" data-rating="${review.fun_rating}"></span></p>
                            <p><strong>Realism:</strong> <span class="stars" data-rating="${review.realism_rating}"></span></p>
                        </div>
                        ${review.comment ? `<p class="review-comment">${review.comment}</p>` : ''}
                        <small class="text-muted">Reviewed on ${review.created_at}</small>
                    </div>
                </div>
            `);
            
            reviewsList.append(reviewElement);
        });
        
        container.append(reviewsList);
        initializeStarRatings(); // Reinitialize stars for the newly added reviews
    }
    
    // Show review modal
    $('#add-review-btn').on('click', function() {
        // Reset form for new review
        $('#review-form')[0].reset();
        setDefaultRatingValues(3);
        $('#reviewModalLabel').text('Review Host: ' + $('h1.mb-0').text());
        
        const reviewModal = new bootstrap.Modal(document.getElementById('reviewModal'));
        reviewModal.show();
    });
    
    $('#edit-review-btn').on('click', function() {
        // Load existing review data
        $.ajax({
            url: `/api/host/${hostId}/user_review`,
            type: 'GET',
            success: function(response) {
                if (response.success) {
                    const review = response.review;
                    $('#difficulty_rating_input').val(review.difficulty_rating);
                    $('#fun_rating_input').val(review.fun_rating);
                    $('#realism_rating_input').val(review.realism_rating);
                    $('#comment').val(review.comment || '');
                        
                    // Update star display
                    setDefaultRatingValues(3); // Reset first
                    $('.rating-input#difficulty-rating i').eq(review.difficulty_rating - 1).click();
                    $('.rating-input#fun-rating i').eq(review.fun_rating - 1).click();
                    $('.rating-input#realism-rating i').eq(review.realism_rating - 1).click();
                }
            }
        });
        
        $('#reviewModalLabel').text('Edit Your Review');
        const reviewModal = new bootstrap.Modal(document.getElementById('reviewModal'));
        reviewModal.show();
    });
    
    // Delete review
    $('#delete-review-btn').on('click', function() {
        if (confirm('Are you sure you want to delete your review?')) {
            $.ajax({
                url: `/api/host/${hostId}/review`,
                type: 'DELETE',
                headers: {
                    'X-CSRFToken': getCsrfToken()
                },
                success: function(response) {
                    if (response.success) {
                        location.reload();
                    } else {
                        alert(response.message || 'Error deleting review');
                    }
                },
                error: function(xhr) {
                    alert('Error deleting review: ' + (xhr.responseJSON?.message || xhr.statusText));
                }
            });
        }
    });
    
    // Submit review
    $('#submit-review').on('click', function() {
        const reviewData = {
            difficulty_rating: parseInt($('#difficulty_rating_input').val()),
            fun_rating: parseInt($('#fun_rating_input').val()),
            realism_rating: parseInt($('#realism_rating_input').val()),
            comment: $('#comment').val()
        };
        
        $.ajax({
            url: `/api/host/${hostId}/review`,
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(reviewData),
            headers: {
                'X-CSRFToken': getCsrfToken()
            },
            success: function(response) {
                if (response.success) {
                    updateStarRatings();
                    bootstrap.Modal.getInstance(document.getElementById('reviewModal')).hide();
                    loadReviews();
                    // Reload page to update average ratings
                    location.reload();
                } else {
                    alert(response.message || 'Error submitting review');
                }
            },
            error: function(xhr) {
                alert('Error submitting review: ' + (xhr.responseJSON?.message || xhr.statusText));
            }
        });
    });
    
    function updateStarRatings() {
        $('.rating-input').each(function() {
            const value = $(this).siblings('input[type="hidden"]').val();
            $(this).find('i').removeClass('active');
            $(this).find('i').each(function() {
                if ($(this).data('value') <= value) {
                    $(this).addClass('active');
                }
            });
        });
    }
});
