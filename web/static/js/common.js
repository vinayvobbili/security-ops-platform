// Common music/audio logic for all pages

// Fetch a random audio file from the backend and set it as the music src
async function setRandomAudio() {
    const music = document.getElementById('music');
    const icon = document.getElementById('music-icon');
    if (!music || !icon) return;
    try {
        const response = await fetch('/api/random-audio');
        const data = await response.json();
        if (data.filename) {
            music.src = '/static/audio/' + data.filename;
        }
    } catch (e) {
        // fallback: keep default src
    }
    music.pause();
    icon.src = '/static/icons/volume-xmark-solid.svg';
}

// Toggle audio mute/unmute and update icon
function toggleAudio() {
    const music = document.getElementById('music');
    const icon = document.getElementById('music-icon');
    if (!music || !icon) return;
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

// Enhanced: Persist music state (currentTime, muted, playing) across page navigation
function persistMusicState() {
    const music = document.getElementById('music');
    if (!music) return;
    localStorage.setItem('music-current-time', music.currentTime);
    localStorage.setItem('music-muted', music.muted);
    localStorage.setItem('music-playing', !music.paused);
}

function restoreMusicState() {
    const music = document.getElementById('music');
    const icon = document.getElementById('music-icon');
    if (!music || !icon) return;
    const savedTime = parseFloat(localStorage.getItem('music-current-time'));
    if (!isNaN(savedTime)) music.currentTime = savedTime;
    const muted = localStorage.getItem('music-muted');
    if (muted !== null) music.muted = (muted === 'true');
    const playing = localStorage.getItem('music-playing');
    if (playing === 'true' && !music.muted) {
        music.play();
        icon.src = '/static/icons/volume-high-solid.svg';
    } else {
        music.pause();
        icon.src = '/static/icons/volume-xmark-solid.svg';
    }
}

// Initialize music on DOMContentLoaded
function initRandomMusic() {
    document.addEventListener('DOMContentLoaded', async function() {
        await setRandomAudio();
        restoreMusicState();
        const music = document.getElementById('music');
        if (music) {
            music.addEventListener('timeupdate', persistMusicState);
            music.addEventListener('play', persistMusicState);
            music.addEventListener('pause', persistMusicState);
            music.addEventListener('volumechange', persistMusicState);
        }
        window.addEventListener('beforeunload', persistMusicState);
    });
}
