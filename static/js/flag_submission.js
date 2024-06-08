function submitFlag(hostId, flagType) {
    var flag = document.getElementById(flagType + '-flag-' + hostId).value;
    fetch('/ctf/submit_flag_api', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            'flag': flag,
            'flag_type': flagType,
            'host_id': hostId
        })
    })
    .then(response => response.json())
    .then(data => {
        alert('Flag submission result: ' + data.result);
    });
}