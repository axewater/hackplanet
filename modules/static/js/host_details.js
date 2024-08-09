$(document).ready(function() {
    function getCsrfToken() {
        return $('input[name="csrf_token"]').val();
    }

    function performAction(action) {
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
                        $('#result').html("<h2>VM Status:</h2><p>" + response.message + "</p>");
                    } else {
                        $('#result').html("<p>" + response.message + "</p>");
                    }
                } else {
                    $('#result').html("<p>Error: " + response.message + "</p>");
                }
            },
            error: function(xhr, status, error) {
                $('#loading').hide();
                $('#result').html("<p>Error: " + error + "</p>");
            }
        });
    }

    $('#start-btn').click(function() { performAction('start'); });
    $('#stop-btn').click(function() { performAction('stop'); });
    $('#status-btn').click(function() { performAction('status'); });
    $('#refresh-btn').click(function() { location.reload(); });
});
