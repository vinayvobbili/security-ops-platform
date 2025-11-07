function submitVerification(response) {
    // Show modal with spinner
    const modal = document.getElementById('responseModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalMessage = document.getElementById('modalMessage');
    const spinner = document.getElementById('spinner');

    modal.style.display = 'block';
    spinner.style.display = 'block';
    modalTitle.textContent = 'Processing...';
    modalMessage.textContent = 'Please wait while we record your response.';

    // Get verification data from the data attributes
    const verificationData = document.getElementById('verificationData');

    // Prepare form data
    const formData = new FormData();
    formData.append('recognized', response);
    formData.append('ticket_id', verificationData.dataset.ticketId);
    formData.append('task_id', verificationData.dataset.taskId);
    formData.append('command', verificationData.dataset.command);
    formData.append('timestamp', verificationData.dataset.timestamp);
    formData.append('system', verificationData.dataset.system);

    // Submit to server
    fetch('/submit-command-verification', {
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            spinner.style.display = 'none';
            if (data.status === 'success') {
                modalTitle.textContent = 'Thank You!';
                modalMessage.textContent = data.message || 'Your response has been recorded successfully.';

                // Close modal after 3 seconds
                setTimeout(() => {
                    modal.style.display = 'none';
                }, 3000);
            } else {
                modalTitle.textContent = 'Error';
                modalMessage.textContent = 'There was an error submitting your response. Please try again or contact support.';
            }
        })
        .catch(error => {
            spinner.style.display = 'none';
            modalTitle.textContent = 'Error';
            modalMessage.textContent = 'Network error. Please check your connection and try again.';
            console.error('Error:', error);
        });
}

// Close modal when clicking outside of it
window.onclick = function (event) {
    const modal = document.getElementById('responseModal');
    if (event.target === modal) {
        modal.style.display = 'none';
    }
}

