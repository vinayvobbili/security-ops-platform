document.getElementById('travelForm').addEventListener('submit', function (event) {
    event.preventDefault();

    const form = event.target;
    const formData = new FormData(form);

    // Format dates from YYYY-MM-DD to MM/DD/YYYY
    const startDate = new Date(formData.get('vacation_start_date'));
    const endDate = new Date(formData.get('vacation_end_date'));

    formData.set('vacation_start_date',
        `${startDate.getMonth() + 1}/${startDate.getDate()}/${startDate.getFullYear()}`);
    formData.set('vacation_end_date',
        `${endDate.getMonth() + 1}/${endDate.getDate()}/${endDate.getFullYear()}`);

    // Convert checkbox value to boolean
    formData.set('will_work_during_vacation',
        document.getElementById('workDuringVacation').checked);

    fetch('/submit-travel-form', {
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                document.getElementById('trackingId').textContent = data.new_incident_id;
                document.getElementById('incidentLink').href = data.new_incident_link;
                document.getElementById('successMessage').style.display = 'block';
                document.getElementById('errorMessage').style.display = 'none';
                form.reset();
            } else {
                document.getElementById('errorMessage').style.display = 'block';
                document.getElementById('successMessage').style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('errorMessage').style.display = 'block';
            document.getElementById('successMessage').style.display = 'none';
        });
});

document.addEventListener('DOMContentLoaded', function () {
    // Get form element
    const travelForm = document.getElementById('travelForm');

    // Create spinner element
    const spinner = document.createElement('div');
    spinner.className = 'spinner';
    spinner.innerHTML = '<div class="spinner-border" role="status"><span class="sr-only">Submitting...</span></div>';
    spinner.style.display = 'none';
    document.body.appendChild(spinner);

    // Create fireworks container
    const fireworksContainer = document.createElement('div');
    fireworksContainer.className = 'fireworks-container';
    document.body.appendChild(fireworksContainer);

    // Add fireworks CSS
    const fireworksStyle = document.createElement('style');
    fireworksStyle.textContent = `
        .fireworks-container {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 999;
        }
        .firework {
            position: absolute;
            width: 5px;
            height: 5px;
            border-radius: 50%;
            animation: explode 1s ease-out forwards;
        }
        @keyframes explode {
            0% { transform: scale(1); opacity: 1; }
            100% { transform: scale(30); opacity: 0; }
        }
    `;
    document.head.appendChild(fireworksStyle);

    // Create success dialog
    const successDialog = document.createElement('div');
    successDialog.className = 'modal-overlay';
    successDialog.innerHTML = `
        <div class="modal-content">
            <p>Your record has been successfully submitted. Enjoy your vacation!</p>
            <button id="okButton" class="btn-primary">OK</button>
        </div>
    `;
    successDialog.style.display = 'none';
    document.body.appendChild(successDialog);

    // Function to create fireworks
    function createFireworks() {
        fireworksContainer.innerHTML = '';
        const colors = ['#ff0000', '#ffff00', '#00ff00', '#00ffff', '#0000ff', '#ff00ff'];

        for (let i = 0; i < 20; i++) {
            setTimeout(() => {
                const firework = document.createElement('div');
                firework.className = 'firework';
                firework.style.backgroundColor = colors[Math.floor(Math.random() * colors.length)];
                firework.style.left = Math.random() * 100 + '%';
                firework.style.top = Math.random() * 100 + '%';
                fireworksContainer.appendChild(firework);

                setTimeout(() => {
                    firework.remove();
                }, 1000);
            }, i * 150);
        }
    }

    // SINGLE form submit handler
    travelForm.addEventListener('submit', function (event) {
        event.preventDefault();

        // Show spinner
        spinner.style.display = 'flex';

        const form = event.target;
        const formData = new FormData(form);

        // Format dates from YYYY-MM-DD to MM/DD/YYYY
        const startDate = new Date(formData.get('vacation_start_date'));
        const endDate = new Date(formData.get('vacation_end_date'));

        formData.set('vacation_start_date',
            `${startDate.getMonth() + 1}/${startDate.getDate()}/${startDate.getFullYear()}`);
        formData.set('vacation_end_date',
            `${endDate.getMonth() + 1}/${endDate.getDate()}/${endDate.getFullYear()}`);

        // Convert checkbox value to Yes/No
        const workDuringVacation = document.getElementById('workDuringVacation').checked;
        formData.set('will_work_during_vacation', workDuringVacation ? 'Yes' : 'No');

        fetch('/submit-travel-form', {
            method: 'POST',
            body: formData
        })
            .then(response => response.json())
            .then(data => {
                // Hide spinner
                spinner.style.display = 'none';

                if (data.status === 'success') {
                    // Display fireworks!
                    createFireworks();

                    // Update tracking info
                    if (document.getElementById('trackingId')) {
                        document.getElementById('trackingId').textContent = data.new_incident_id;
                    }
                    if (document.getElementById('incidentLink') && data.new_incident_link) {
                        document.getElementById('incidentLink').href = data.new_incident_link;
                    }

                    // Show success message
                    successDialog.style.display = 'flex';

                    if (document.getElementById('successMessage')) {
                        document.getElementById('successMessage').style.display = 'block';
                    }
                    if (document.getElementById('errorMessage')) {
                        document.getElementById('errorMessage').style.display = 'none';
                    }
                } else {
                    if (document.getElementById('errorMessage')) {
                        document.getElementById('errorMessage').style.display = 'block';
                    }
                    if (document.getElementById('successMessage')) {
                        document.getElementById('successMessage').style.display = 'none';
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
                spinner.style.display = 'none';

                if (document.getElementById('errorMessage')) {
                    document.getElementById('errorMessage').style.display = 'block';
                }
                if (document.getElementById('successMessage')) {
                    document.getElementById('successMessage').style.display = 'none';
                }

                alert('An error occurred while submitting the form. Please try again.');
            });
    });

    // Add OK button handler
    document.getElementById('okButton').addEventListener('click', function () {
        // Hide success dialog
        successDialog.style.display = 'none';

        // Clear form fields
        travelForm.reset();

        // Set focus to email field
        document.getElementById('traveller_email_address').focus();
    });

    document.getElementById('traveller_email_address').focus();
});