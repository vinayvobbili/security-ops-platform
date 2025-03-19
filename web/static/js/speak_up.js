document.addEventListener('DOMContentLoaded', function () {
    let today = new Date();
    const dd = String(today.getDate()).padStart(2, '0');
    const mm = String(today.getMonth() + 1).padStart(2, '0');
    const yyyy = today.getFullYear();
    const todayString = yyyy + '-' + mm + '-' + dd;
    const dateInput = document.querySelector('input[type="date"]');
    if (dateInput) {
        dateInput.setAttribute('max', todayString);
    }
    // Get the modal
    const modal = document.getElementById("responseModal");
    if (modal) {
        // Ensure the modal does not have the show class initially
        modal.classList.remove("show");
    }
});

document.getElementById('speakUpForm').addEventListener('submit', function (event) {
    event.preventDefault(); // Prevent the default form submission

    const formData = new FormData(this);

    fetch('/submit-speak-up-form', {
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            const responseDiv = document.getElementById('response');
            if (responseDiv) {
                responseDiv.innerHTML = `
                 <h3>Report submitted successfully!</h3>
                 <p><strong>XSOAR Ticket#:</strong> <a href="${data.new_incident_link}" target="_blank">${data.new_incident_id}</a></p>
                `;

                // Get the modal
                const modal = document.getElementById("responseModal");
                if (modal) {
                    // Show the modal
                    modal.classList.add("show");

                    // Get the <span> element that closes the modal
                    const span = document.getElementsByClassName("close")[0];

                    // When the user clicks on <span> (x), close the modal
                    if (span) {
                        span.onclick = function () {
                            modal.classList.remove("show");
                        }
                    }
                    // When the user clicks anywhere outside the modal, close it
                    window.onclick = function (event) {
                        if (event.target === modal) {
                            modal.classList.remove("show");
                        }
                    }
                }
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
});