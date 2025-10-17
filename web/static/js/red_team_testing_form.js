document.addEventListener("DOMContentLoaded", function () {
    const usernamesField = document.getElementById("usernames");
    if (usernamesField) {
        usernamesField.focus();
    }

    const form = document.getElementById('red-team-testing-form');
    if (form) {
        form.onsubmit = async function(e) {
            e.preventDefault();
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
                        const usernamesField = document.getElementById('usernames');
                        if (usernamesField) {
                            setTimeout(() => usernamesField.focus(), 50);
                        }
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
                            const usernamesField = document.getElementById('usernames');
                            if (usernamesField) {
                                setTimeout(() => usernamesField.focus(), 50);
                            }
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
    }
});
// --- Audio randomization and toggle logic ---
const audioFiles = [
    'background-music-upbeat-374859.mp3',
    'bollywood-indian-hindi-song-music-370833.mp3',
    'calm-soft-piano-music-378287.mp3',
    'chasing-sunshine_medium-1-378263.mp3',
    'embrace-364091.mp3',
    'eona-emotional-ambient-pop-351436.mp3',
    'exciting-upbeat-background-music-378310.mp3',
    'inspirational-uplifting-calm-piano-254764.mp3',
    'jungle-waves-drumampbass-electronic-inspiring-promo-345013.mp3',
    'no-copyright-music-corporate-background-377662.mp3',
    'relaxing-krishna-flute-music-deep-sleep-relaxing-music-292793.mp3',
    'the-best-jazz-club-in-new-orleans-164472.mp3'
];
function getRandomAudioFile() {
    return audioFiles[Math.floor(Math.random() * audioFiles.length)];
}
document.addEventListener('DOMContentLoaded', function () {
    // ...existing code...
    const music = document.getElementById('music');
    const icon = document.getElementById('music-icon');
    if (music && icon) {
        music.src = '/static/audio/' + getRandomAudioFile();
        music.pause();
        icon.src = '/static/icons/volume-xmark-solid.svg';
    }
});
window.toggleAudio = function() {
    const music = document.getElementById('music');
    const icon = document.getElementById('music-icon');
    if (music && icon) {
        if (music.muted) {
            music.muted = false;
            music.play();
            icon.src = '/static/icons/volume-high-solid.svg';
        } else {
            music.muted = true;
            music.pause();
            icon.src = '/static/icons/volume-xmark-solid.svg';
        }
    }
};
