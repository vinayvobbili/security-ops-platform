const subcategoryOptions = {
    network: ['Router', 'Switch', 'Firewall'],
    server: ['Web Server', 'Database Server', 'File Server'],
    application: ['Web App', 'Mobile App', 'Desktop App']
};

document.getElementById('category').addEventListener('change', function () {
    const category = this.value;
    const subcategorySelect = document.getElementById('subcategory');
    subcategorySelect.innerHTML = ''; // Clear existing options

    const defaultOption = document.createElement('option');
    defaultOption.value = "";
    defaultOption.textContent = "Select Subcategory";
    subcategorySelect.appendChild(defaultOption);

    // Check if the category exists in subcategoryOptions
    if (subcategoryOptions[category]) {
        subcategoryOptions[category].forEach(function (subcategory) {
            const option = document.createElement('option');
            option.value = subcategory;
            option.textContent = subcategory;
            subcategorySelect.appendChild(option);
        });
    }
});

// Clear button functionality
document.getElementById('clearButton').addEventListener('click', function () {
    // Reset all form fields
    document.getElementById('msocForm').reset();

    // Reset subcategory dropdown
    const subcategorySelect = document.getElementById('subcategory');
    subcategorySelect.innerHTML = '';

    const defaultOption = document.createElement('option');
    defaultOption.value = "";
    defaultOption.textContent = "Select Subcategory";
    subcategorySelect.appendChild(defaultOption);

    // Trigger change event on category dropdown to re-populate subcategory
    document.getElementById('category').dispatchEvent(new Event('change'));

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
            const responseDiv = document.getElementById('response');
            responseDiv.innerHTML = `
             <h3>Form submitted successfully!</h3>
             <p><strong>XSOAR Ticket#:</strong> ${data.new_incident_id}</p>
             <p><strong>Ticket Link:</strong> <a href="${data.new_incident_link}" target="_blank">${data.new_incident_link}</a></p>
            `;

            // Get the modal
            const modal = document.getElementById("responseModal");
            // Show the modal
            modal.style.display = "block";

            // Get the <span> element that closes the modal
            const span = document.getElementsByClassName("close")[0];

            // When the user clicks on <span> (x), close the modal
            span.onclick = function () {
                modal.style.display = "none";
            }
            // When the user clicks anywhere outside of the modal, close it
            window.onclick = function (event) {
                if (event.target == modal) {
                    modal.style.display = "none";
                }
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
})