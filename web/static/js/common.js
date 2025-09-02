// Common music/audio logic for all pages

// Fetch a random audio file from the backend and set it as the music src
async function setRandomAudio() {
    const music = document.getElementById('music');
    const icon = document.getElementById('music-icon');
    if (!music || !icon) return;
    
    // Check if we have a saved audio source from previous navigation
    const savedSrc = localStorage.getItem('music-src');
    
    if (savedSrc && savedSrc.includes('/static/audio/')) {
        // Use previously saved audio source to maintain continuity (only if it's actually an audio file)
        music.src = savedSrc;
        console.log('Using saved audio:', savedSrc);
    } else {
        // Clear invalid saved source
        if (savedSrc && !savedSrc.includes('/static/audio/')) {
            localStorage.removeItem('music-src');
            console.log('Cleared invalid saved audio source:', savedSrc);
        }
        
        if (!music.src || music.src === window.location.origin + '/' || !music.src.includes('/static/audio/')) {
            // Only fetch new random audio if no valid audio source exists
            try {
                const response = await fetch('/api/random-audio');
                const data = await response.json();
                if (data.filename) {
                    const newSrc = '/static/audio/' + data.filename;
                    music.src = newSrc;
                    localStorage.setItem('music-src', newSrc);
                    console.log('Set new random audio:', newSrc);
                }
            } catch (e) {
                console.error('Failed to fetch random audio:', e);
            }
        }
    }
    
    // Always start muted on page load
    music.muted = true;
    music.pause();
    icon.src = '/static/icons/volume-xmark-solid.svg';
    
    // Add error event listener to debug loading issues
    music.addEventListener('error', (e) => {
        console.error('Audio loading error:', e, 'Source:', music.src);
    });
    
    music.addEventListener('loadeddata', () => {
        console.log('Audio loaded successfully:', music.src);
    });
}

// Toggle audio mute/unmute and update icon
function toggleAudio() {
    const music = document.getElementById('music');
    const icon = document.getElementById('music-icon');
    console.log('Toggle audio called - music:', !!music, 'icon:', !!icon, 'src:', music?.src, 'muted:', music?.muted);
    if (!music || !icon || !music.src) return;
    
    if (music.muted) {
        music.muted = false;
        
        // Wait for audio to be ready before playing
        const tryPlay = () => {
            music.play().then(() => {
                console.log('Audio playing successfully');
            }).catch(e => {
                console.error('Audio play failed:', e);
                console.log('Audio state:', {
                    src: music.src,
                    readyState: music.readyState,
                    networkState: music.networkState,
                    error: music.error
                });
            });
        };
        
        if (music.readyState >= 3) {
            // Audio is already loaded enough to play
            tryPlay();
        } else {
            // Wait for audio to load
            music.addEventListener('canplay', tryPlay, { once: true });
            music.load(); // Force reload if needed
        }
        
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
