function submitFlag(id, flagType) {
    console.log('ID:', id);
    console.log('Flag Type:', flagType);
    
    var flag = document.getElementById(flagType + '-flag-' + id).value;
    console.log('Flag:', flag);

    let url;
    if (flagType === 'challenge') {
        url = `/ctf/submit_challenge_flag_api?flag=${encodeURIComponent(flag)}&challenge_id=${id}`;
    } else {
        url = `/ctf/submit_flag_api?flag=${encodeURIComponent(flag)}&host_id=${id}&flag_type=${flagType}`;
    }
    console.log('Submitting flag:', url);

    fetch(url)
    .then(response => {
        console.log('Response received:', response);
        return response.json();
    })
    .then(data => {
        console.log('Response data:', data);
        if (data.error) {
            console.error('Error:', data.error);
            showModal(data.error.includes('already submitted') ? '😕' : '❌', data.error);
        } else {
            console.log('Flag submission result:', data.result);
            showModal('✅', 'Flag submission result: ' + data.result);
        }
    })
    .catch(error => {
        console.error('An error occurred while submitting the flag:', error);
        showModal('❌', 'An error occurred while submitting the flag. Please try again.');
    });
}

function showModal(emoticon, message) {
    const modal = document.getElementById('flagModal');
    const modalEmoticon = document.getElementById('modalEmoticon');
    const modalMessage = document.getElementById('modalMessage');

    modalEmoticon.textContent = emoticon;
    modalMessage.textContent = message;

    modal.style.display = 'block';

    setTimeout(() => {
        modal.style.display = 'none';
    }, 5000);
}
