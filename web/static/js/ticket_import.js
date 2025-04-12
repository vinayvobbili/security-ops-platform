document.getElementById('xsoarTicketImportForm').addEventListener('submit', function (event) {
    event.preventDefault(); // Prevent the default form submission

    // Show loading indicator
    document.getElementById('loading').style.display = 'block';

    const formData = new FormData(this);

    fetch('/import-xsoar-ticket', {
        method: 'POST',
        body: formData
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Hide loading indicator
            document.getElementById('loading').style.display = 'none';

            // Update the response div with the new incident details
            const responseDiv = document.getElementById('response');
            responseDiv.innerHTML = `
      <div class="result-card">
        <h3 class="result-title">
          <span class="success-icon">✓</span>
          Ticket imported successfully!
        </h3>
        <div class="info-row">
          <div class="info-label">Source Ticket#:</div>
          <div class="info-value">${data.source_ticket_number}</div>
        </div>
        <div class="info-row">
          <div class="info-label">Destination Ticket#:</div>
          <div class="info-value">${data.destination_ticket_number}</div>
        </div>
        <div class="info-row">
          <div class="info-label">Destination Link:</div>
          <div class="info-value url-container">
            <a href="${data.destination_ticket_link}" target="_blank">${data.destination_ticket_link}</a>
            <button class="copy-btn" data-clipboard="${data.destination_ticket_link}">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
            </button>
          </div>
        </div>
      </div>
    `;

            // Add copy button functionality
            document.querySelectorAll('.copy-btn').forEach(button => {
                button.addEventListener('click', function () {
                    const textToCopy = this.getAttribute('data-clipboard');
                    navigator.clipboard.writeText(textToCopy).then(() => {
                        // Change button appearance temporarily to show success
                        const originalHTML = this.innerHTML;
                        this.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
          `;
                        this.classList.add('copied');

                        // Reset after 2 seconds
                        setTimeout(() => {
                            this.innerHTML = originalHTML;
                            this.classList.remove('copied');
                        }, 2000);
                    }).catch(err => {
                        console.error('Could not copy text: ', err);
                    });
                });
            });

            // Add show class for animation
            setTimeout(() => {
                responseDiv.classList.add('show');
            }, 10);
        })
        .catch(error => {
            // Hide loading indicator
            document.getElementById('loading').style.display = 'none';

            console.error('Error:', error);

            // Show error message
            document.getElementById('response').innerHTML = `
      <div class="result-card" style="border-left-color: #dc3545;">
        <h3 class="result-title" style="color: #dc3545;">
          <span class="success-icon" style="background: #dc3545;">✕</span>
          Error importing ticket
        </h3>
        <p>There was a problem processing your request. Please try again.</p>
      </div>
    `;

            // Add show class for animation
            setTimeout(() => {
                document.getElementById('response').classList.add('show');
            }, 10);
        });
});