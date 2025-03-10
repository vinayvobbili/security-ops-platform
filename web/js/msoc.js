const subcategoryOptions = {
    network: ['Router', 'Switch', 'Firewall'],
    server: ['Web Server', 'Database Server', 'File Server'],
    application: ['Web App', 'Mobile App', 'Desktop App']
};

document.getElementById('category').addEventListener('change', function () {
    const category = this.value;
    const subcategorySelect = document.getElementById('subcategory');
    subcategorySelect.innerHTML = ''; // Clear existing options

    subcategoryOptions[category].forEach(function (subcategory) {
        const option = document.createElement('option');
        option.value = subcategory;
        option.textContent = subcategory;
        subcategorySelect.appendChild(option);
    });
});

document.getElementById('msocForm').addEventListener('submit', function (event) {
    event.preventDefault(); // Prevent the default form submission

    const formData = new FormData(this);

    fetch('/submit-msoc-form', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('response').innerHTML = `
            <h3>Form submitted successfully!</h3>
            <p><strong>XSOAR Ticket#:</strong> ${data.new_incident_id}</p>
            <p><strong>Ticket Link:</strong> <a href="${data.new_incident_link}" target="_blank">${data.new_incident_link}</a></p>
        `;
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

// Trigger change event to populate subcategory on page load
document.getElementById('category').dispatchEvent(new Event('change'));
