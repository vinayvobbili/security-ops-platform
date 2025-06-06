document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("usernames").focus();
});

document.getElementById('red-team-testing-form').onsubmit = async function(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    // Show loading spinner
    document.getElementById('loading').style.display = 'block';
    document.getElementById('result').innerHTML = '';
    try {
        const response = await fetch(form.action, {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        // Hide loading spinner
        document.getElementById('loading').style.display = 'none';
        if (result.status === 'success') {
            const dialog = document.getElementById('successDialog');
            const entryDetails = document.getElementById('entryDetails');
            const dialogHeading = document.getElementById('dialogHeading');
            dialogHeading.textContent = 'Entry submitted successfully';
            let html = '<ul style="text-align:left">';
            for (const [key, value] of Object.entries(result.entry || {})) {
                html += `<li><b>${key}:</b> ${value}</li>`;
            }
            html += '</ul>';
            entryDetails.innerHTML = html;
            dialog.showModal();
            form.reset();
            document.getElementById('okBtn').onclick = function() {
                dialog.close();
                setTimeout(() => document.getElementById('usernames').focus(), 50);
            };
        } else {
            let errorMsg = result.message || result.error || 'Submission failed. Please try again.';
            if (errorMsg === 'At least one of Usernames, Tester Hosts, or Targets must be filled.') {
                const dialog = document.getElementById('successDialog');
                const entryDetails = document.getElementById('entryDetails');
                const dialogHeading = document.getElementById('dialogHeading');
                dialogHeading.textContent = 'Submission failed';
                entryDetails.innerHTML = `<p style='color:#c0392b;'>${errorMsg}</p>`;
                dialog.showModal();
                document.getElementById('okBtn').onclick = function() {
                    dialog.close();
                    setTimeout(() => document.getElementById('usernames').focus(), 50);
                };
            } else {
                document.getElementById('result').innerHTML = `<p style="color:#c0392b;">${errorMsg}</p>`;
            }
        }
    } catch (err) {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('result').innerHTML = `<p style="color:#c0392b;">${err.message || 'Submission failed. Please try again.'}</p>`;
    }
};
