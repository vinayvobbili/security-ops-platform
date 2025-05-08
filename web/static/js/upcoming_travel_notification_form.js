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

    // Add form submit handler
    travelForm.addEventListener('submit', function (e) {
        e.preventDefault();

        // Show spinner
        spinner.style.display = 'flex';

        // Get form data
        const formData = new FormData(travelForm);

        // Convert checkbox value to Yes/No
        const workDuringVacation = document.getElementById('workDuringVacation').checked;
        formData.set('will_work_during_vacation', workDuringVacation ? 'Yes' : 'No');

        // Submit form data
        fetch('/submit-travel-form', {
            method: 'POST',
            body: formData
        })
            .then(response => response.json())
            .then(data => {
                // Hide spinner
                spinner.style.display = 'none';

                // Show success dialog
                if (data.status === 'success') {
                    successDialog.style.display = 'flex';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                spinner.style.display = 'none';
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