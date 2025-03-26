$(document).ready(function() {
    // Get the host ID from the URL
    var hostId = getHostIdFromUrl();

    // Fetch host details and render the page
    fetchHostDetails(hostId);

    // Handle review form submission
    $('#review-form').on('submit', function(event) {
        event.preventDefault();
        submitHostReview(hostId);
    });

    // Handle add review button click
    $('#add-review-btn').on('click', function() {
        // Reset form for new review
        var reviewForm = document.getElementById('review-form');
        if (reviewForm) {
            reviewForm.reset();
        }
        setDefaultRatingValues(3);
        $('#reviewModalLabel').text('Review Host: ' + $('h1.mb-0').text());
        const reviewModal = new bootstrap.Modal(document.getElementById('reviewModal'));
        reviewModal.show();
    });
});

function getHostIdFromUrl() {
    var url = new URL(window.location.href);
    return url.searchParams.get('id');
}

function fetchHostDetails(hostId) {
    $.ajax({
        url: '/api/hosts/' + hostId,
        type: 'GET',
        success: function(data) {
            renderHostDetails(data);
        },
        error: function(xhr, status, error) {
            console.error('Error fetching host details:', error);
        }
    });
}

function renderHostDetails(hostData) {
    // Populate host details
    $('h1.mb-0').text(hostData.name);
    $('#host-description').text(hostData.description);
    $('#host-response-time').text(hostData.response_time);
    $('#host-response-rate').text(hostData.response_rate + '%');
    $('#host-rating').text(hostData.rating.toFixed(1));
    $('#host-num-reviews').text(hostData.num_reviews);

    // Render host reviews
    var reviewsContainer = $('#host-reviews');
    reviewsContainer.empty();

    hostData.reviews.forEach(function(review) {
        var reviewElement = createReviewElement(review);
        reviewsContainer.append(reviewElement);
    });
}

function createReviewElement(review) {
    var reviewElement = $('<div>').addClass('review mb-4');

    var reviewerName = $('<h5>').addClass('mb-1').text(review.reviewer_name);
    var reviewRating = $('<div>').addClass('review-rating mb-2').html(createRatingStars(review.rating));
    var reviewText = $('<p>').addClass('mb-0').text(review.text);

    reviewElement.append(reviewerName, reviewRating, reviewText);
    return reviewElement;
}

function createRatingStars(rating) {
    var stars = '';
    for (var i = 0; i < 5; i++) {
        if (i < Math.floor(rating)) {
            stars += '<i class="fas fa-star"></i>';
        } else if (i === Math.floor(rating) && rating % 1 !== 0) {
            stars += '<i class="fas fa-star-half-alt"></i>';
        } else {
            stars += '<i class="far fa-star"></i>';
        }
    }
    return stars;
}

function setDefaultRatingValues(rating) {
    $('.rating-input').val(rating);
    $('.rating-display').html(createRatingStars(rating));
}

function submitHostReview(hostId) {
    var reviewData = {
        rating: $('#review-rating').val(),
        text: $('#review-text').val(),
        reviewer_name: $('#review-name').val()
    };

    $.ajax({
        url: '/api/hosts/' + hostId + '/reviews',
        type: 'POST',
        data: JSON.stringify(reviewData),
        contentType: 'application/json',
        success: function(data) {
            // Refresh the host details and reviews
            fetchHostDetails(hostId);
            const reviewModal = new bootstrap.Modal(document.getElementById('reviewModal'));
            reviewModal.hide();
        },
        error: function(xhr, status, error) {
            console.error('Error submitting host review:', error);
        }
    });
}
