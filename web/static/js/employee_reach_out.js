function submitVerification(response) {
    // Validate file size before submission
    const fileUpload = document.getElementById('fileUpload');
    const fileError = document.getElementById('fileError');
    const maxSize = 10 * 1024 * 1024; // 10MB in bytes

    if (fileUpload.files.length > 0) {
        const file = fileUpload.files[0];
        if (file.size > maxSize) {
            fileError.textContent = `File size (${(file.size / 1024 / 1024).toFixed(2)}MB) exceeds the maximum limit of 10MB. Please select a smaller file.`;
            fileError.style.display = 'block';
            return; // Stop submission
        } else {
            fileError.style.display = 'none';
        }
    }

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

    // Add comments if provided
    const comments = document.getElementById('comments').value;
    if (comments.trim()) {
        formData.append('comments', comments);
    }

    // Add file if provided
    if (fileUpload.files.length > 0) {
        formData.append('file', fileUpload.files[0]);
    }

    // Submit to server
    fetch('/submit-employee-response', {
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            spinner.style.display = 'none';
            if (data.status === 'success') {
                // Replace entire page with Thank You message
                document.body.innerHTML = `
                    <div class="container">
                        <div class="inner-container">
                            <div class="header">
                                <div class="header-content">
                                    <div class="logo-section">
                                        <img alt="MetLife" src="/static/images/MetLife logo dark.webp" style="background: transparent;"/>
                                    </div>
                                    <div class="header-text">
                                        <h1>Thank You!</h1>
                                        <div class="header-underline"></div>
                                        <p>Cyber Incident Response Team</p>
                                    </div>
                                </div>
                            </div>

                            <div class="separator"></div>

                            <div class="content">
                                <div class="success-box">
                                    <div style="font-size: 64px; margin-bottom: 20px;">✅</div>
                                    <h2>Response Recorded Successfully</h2>
                                    <p class="subtitle">${data.message || 'Your response has been recorded successfully.'}</p>
                                    <p class="subtitle" style="margin-top: 30px; font-size: 18px; font-weight: 600;">
                                        You may now close this window.
                                    </p>
                                </div>
                            </div>

                            <div class="separator"></div>

                            <div class="footer">
                                <p>For questions or concerns, contact the Security Operations Center:<br>
                                    <a href="mailto:security@company.com">📧 security@company.com</a>
                                </p>
                                <div class="footer-divider">
                                    <p class="footer-copyright"><strong>MetLife Cyber Incident Response</strong></p>
                                    <p class="footer-legal">&copy; 2025 MetLife. All rights reserved. | Confidential & Proprietary</p>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
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

