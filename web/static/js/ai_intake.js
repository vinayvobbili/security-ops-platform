document.addEventListener('DOMContentLoaded', function () {
    const modal = document.getElementById("responseModal");
    if (modal) {
        modal.classList.remove("show");
    }
});

document.getElementById('aiIntakeForm').addEventListener('submit', function (event) {
    event.preventDefault();

    const submitBtn = this.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting...';

    // Combine email prefix with domain (strip domain if user typed it)
    const domain = document.getElementById('emailDomain').textContent.trim();
    let prefix = document.getElementById('emailPrefix').value.trim();
    if (prefix.toLowerCase().endsWith(domain.toLowerCase())) {
        prefix = prefix.slice(0, -domain.length);
    }
    document.getElementById('email').value = prefix + domain;

    // Validate file sizes (10 MB max each)
    const MAX_FILE_SIZE = 10 * 1024 * 1024;
    const fileInput = document.getElementById('documents');
    const fileError = document.getElementById('fileError');
    if (fileInput && fileInput.files.length > 0) {
        for (const file of fileInput.files) {
            if (file.size > MAX_FILE_SIZE) {
                if (fileError) {
                    fileError.textContent = `"${file.name}" exceeds 10 MB limit.`;
                    fileError.style.display = 'block';
                }
                return;
            }
        }
    }
    if (fileError) fileError.style.display = 'none';

    const formData = new FormData(this);

    fetch('/submit-ai-intake', {
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            const responseDiv = document.getElementById('response');
            if (responseDiv) {
                if (data.status === 'success') {
                    let html = `<h3>Request Submitted Successfully!</h3><p>${data.message}</p>`;
                    if (data.azdo_url) {
                        html += `<p><a href="${data.azdo_url}" target="_blank" rel="noopener noreferrer">View Work Item in Azure DevOps</a></p>`;
                    }
                    responseDiv.innerHTML = html;
                    submitBtn.textContent = '✓ Submitted';
                    document.getElementById('aiIntakeForm').reset();
                } else {
                    responseDiv.innerHTML = `
                        <h3 style="color: #dc3545;">Submission Error</h3>
                        <p>${data.message}</p>
                    `;
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Submit Request';
                }

                const modal = document.getElementById("responseModal");
                if (modal) {
                    modal.classList.add("show");

                    const span = document.getElementsByClassName("close")[0];
                    if (span) {
                        span.onclick = function () {
                            modal.classList.remove("show");
                        }
                    }

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
            submitBtn.disabled = false;
            submitBtn.textContent = 'Submit Request';
            const responseDiv = document.getElementById('response');
            if (responseDiv) {
                responseDiv.innerHTML = `
                    <h3 style="color: #dc3545;">Network Error</h3>
                    <p>Could not submit the form. Please try again.</p>
                `;
                const modal = document.getElementById("responseModal");
                if (modal) {
                    modal.classList.add("show");
                }
            }
        });
});
