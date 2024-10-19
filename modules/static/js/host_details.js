$(document).ready(function() {
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
});
