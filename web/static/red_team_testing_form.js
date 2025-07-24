// ...existing code...
// --- Audio randomization and toggle logic (dynamic fetch) ---
async function setRandomAudio() {
    const music = document.getElementById('music');
    const icon = document.getElementById('music-icon');
    try {
        const response = await fetch('/api/random-audio');
        const data = await response.json();
        if (data.filename) {
            music.src = '/static/audio/' + data.filename;
        }
    } catch (e) {
        // fallback: keep default src
    }
    if (music && icon) {
        music.pause();
        icon.src = '/static/icons/volume-xmark-solid.svg';
    }
}
document.addEventListener('DOMContentLoaded', function () {
    // ...existing code...
    setRandomAudio();
});
// ...existing code...

