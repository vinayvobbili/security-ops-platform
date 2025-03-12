const subcategoryOptions = {
    network: ['Router', 'Switch', 'Firewall'],
    server: ['Web Server', 'Database Server', 'File Server'],
    application: ['Web App', 'Mobile App', 'Desktop App']
};

const music = document.getElementById('music');
const music_icon = document.getElementById('music-icon');

music.volume = 0.5; // Set initial volume (0.0 to 1.0)

function toggleAudio() {
    if (music.muted) {
        music.muted = false;
        music.play();
        music_icon.src = '/static/icons/volume-high-solid.svg';
    } else {
        music.muted = true; // Or music.pause(); if you want to stop playback entirely.
        music_icon.src = '/static/icons/volume-xmark-solid.svg';
    }
}

window.addEventListener('load', (event) => {
    document.getElementById('category').dispatchEvent(new Event('change'));
});

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
    // Apply the loaded class with a delay
    setTimeout(() => {
        subcategorySelect.classList.add('loaded');
    }, 0);
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
             <p><strong>XSOAR Ticket#:</strong> <a href="${data.new_incident_link}" target="_blank">${data.new_incident_id}</a></p>
            `;

            // Get the modal
            const modal = document.getElementById("responseModal");
            // Show the modal
            modal.classList.add("show");

            // Get the <span> element that closes the modal
            const span = document.getElementsByClassName("close")[0];

            // When the user clicks on <span> (x), close the modal
            span.onclick = function () {
                modal.classList.remove("show");
            }
            // When the user clicks anywhere outside of the modal, close it
            window.onclick = function (event) {
                if (event.target == modal) {
                    modal.classList.remove("show");
                }
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
})