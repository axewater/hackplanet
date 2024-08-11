document.addEventListener('DOMContentLoaded', function() {
    const flagForm = document.getElementById('flag-submission-form');
    const flagInput = document.getElementById('flag-input');
    const submitButton = document.getElementById('submit-flag');
    const resultMessage = document.getElementById('result-message');

    flagForm.addEventListener('submit', function(e) {
        e.preventDefault();
        submitFlag();
    });

    function submitFlag() {
        const flag = flagInput.value.trim();
        const challengeId = flagForm.dataset.challengeId;

        if (!flag) {
            showResult('Please enter a flag.', 'error');
            return;
        }

        fetch('/submit_challenge_flag', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({
                challenge_id: challengeId,
                flag: flag
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showResult(data.message, 'success');
                flagInput.value = '';
                updateUserScore(data.new_score);
            } else {
                showResult(data.message, 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showResult('An error occurred. Please try again.', 'error');
        });
    }

    function showResult(message, type) {
        resultMessage.textContent = message;
        resultMessage.className = type;
        resultMessage.style.display = 'block';
    }

    function updateUserScore(newScore) {
        const scoreElement = document.getElementById('user-score');
        if (scoreElement) {
            scoreElement.textContent = newScore;
        }
    }

    function getCsrfToken() {
        return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    }
});
