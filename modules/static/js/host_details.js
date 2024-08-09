$(document).ready(function() {
    function getCsrfToken() {
        return $('input[name="csrf_token"]').val();
    }

    function disableButtons() {
        $('#start-btn, #stop-btn, #status-btn').prop('disabled', true);
    }

    function enableButtons() {
        $('#start-btn, #stop-btn, #status-btn').prop('disabled', false);
    }

    function updateStatusDisplay(status) {
        var statusText = status ? 'Online' : 'Offline';
        $('#status-display').text(statusText);
        $('#status-display').removeClass('text-success text-danger');
        $('#status-display').addClass(status ? 'text-success' : 'text-danger');
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
                    if (action === "status") {
                        $('#status-result').text(response.message);
                        var isRunning = response.message.toLowerCase().includes('vm running');
                        updateStatusDisplay(isRunning);
                    } else {
                        $('#result').html("<p>" + response.message + "</p>");
                        updateStatusDisplay(action === 'start');
                    }
                } else {
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
    $('#status-btn').click(function() { performAction('status'); });
    $('#refresh-btn').click(function() { location.reload(); });
});
