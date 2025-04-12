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
          <div class="info-value">
            <a href="${data.destination_ticket_link}" target="_blank">${data.destination_ticket_link}</a>
          </div>
        </div>
      </div>
    `;

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