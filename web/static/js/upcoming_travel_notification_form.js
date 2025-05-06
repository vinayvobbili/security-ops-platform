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