// Common music/audio logic for all pages

// Fetch a random audio file from the backend and set it as the music src
async function setRandomAudio() {
    const music = document.getElementById('music');
    const icon = document.getElementById('music-icon');
    if (!music || !icon) return;
    
    // Check if we have a saved audio source from previous navigation
    const savedSrc = localStorage.getItem('music-src');
    
    if (savedSrc) {
        // Use previously saved audio source to maintain continuity
        music.src = savedSrc;
    } else if (!music.src || music.src === window.location.origin + '/') {
        // Only fetch new random audio if no source exists
        try {
            const response = await fetch('/api/random-audio');
            const data = await response.json();
            if (data.filename) {
                const newSrc = '/static/audio/' + data.filename;
                music.src = newSrc;
                localStorage.setItem('music-src', newSrc);
            }
        } catch (e) {
            // fallback: keep default src
        }
    }
    
    // Always start muted on page load
    music.muted = true;
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

// Enhanced: Persist music state (currentTime, muted, playing, src) across page navigation
function persistMusicState() {
    const music = document.getElementById('music');
    if (!music) return;
    localStorage.setItem('music-current-time', music.currentTime);
    localStorage.setItem('music-muted', music.muted);
    localStorage.setItem('music-playing', !music.paused);
    if (music.src) localStorage.setItem('music-src', music.src);
}

function restoreMusicState() {
    const music = document.getElementById('music');
    const icon = document.getElementById('music-icon');
    if (!music || !icon) return;
    
    // Restore audio position
    const savedTime = parseFloat(localStorage.getItem('music-current-time'));
    if (!isNaN(savedTime)) music.currentTime = savedTime;
    
    // Check if music was playing before navigation
    const wasPlaying = localStorage.getItem('music-playing') === 'true';
    const wasMuted = localStorage.getItem('music-muted') === 'true';
    
    if (wasPlaying && !wasMuted) {
        // Music was playing before navigation - resume but start muted due to browser policy
        music.muted = false;
        music.play().then(() => {
            icon.src = '/static/icons/volume-high-solid.svg';
        }).catch(() => {
            // If autoplay fails, stay muted
            music.muted = true;
            icon.src = '/static/icons/volume-xmark-solid.svg';
        });
    } else {
        // Start muted
        music.muted = true;
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
