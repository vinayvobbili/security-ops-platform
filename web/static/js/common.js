// Common music/audio logic for all pages

// Fetch a random audio file from the backend and set it as the music src
async function setRandomAudio() {
    const music = document.getElementById('music');
    const icon = document.getElementById('music-icon');
    if (!music || !icon) return;

    // Check if this is a fresh session (browser refresh) or navigation within session
    const sessionId = sessionStorage.getItem('music-session-id');
    const currentSessionId = Date.now().toString();

    // Check if we have a saved audio source from previous navigation in SAME session
    const savedSrc = localStorage.getItem('music-src');

    if (sessionId && savedSrc && savedSrc.includes('/static/audio/')) {
        // Same session, use existing audio for continuity
        music.src = savedSrc;
        console.log('Using saved audio from same session:', savedSrc);
    } else {
        // Fresh session (browser refresh) - get new random audio
        sessionStorage.setItem('music-session-id', currentSessionId);
        try {
            const response = await fetch('/api/random-audio');
            const data = await response.json();
            if (data.filename) {
                const newSrc = '/static/audio/' + data.filename;
                music.src = newSrc;
                localStorage.setItem('music-src', newSrc);
                console.log('Set new random audio for fresh session:', newSrc);
            }
        } catch (e) {
            console.error('Failed to fetch random audio:', e);
            // Fallback: clear any saved source if API fails
            localStorage.removeItem('music-src');
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
            music.addEventListener('canplay', tryPlay, {once: true});
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
    document.addEventListener('DOMContentLoaded', async function () {
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

// Burger menu functionality
function toggleMenu() {
    var menu = document.getElementById('burgerMenu');
    if (menu) {
        menu.style.display = (menu.style.display === 'none' || menu.style.display === '') ? 'block' : 'none';
    }
}

// Initialize burger menu event handlers
function initBurgerMenu() {
    document.addEventListener('DOMContentLoaded', function () {
        var burgerMenu = document.getElementById('burgerMenu');
        if (burgerMenu) {
            // Close menu when a link is clicked
            burgerMenu.querySelectorAll('a').forEach(function (link) {
                link.addEventListener('click', function () {
                    burgerMenu.style.display = 'none';
                });
            });
        }

        // Close burger menu when clicking outside
        document.addEventListener('click', function (e) {
            var burgerMenu = document.getElementById('burgerMenu');
            var navBurger = document.querySelector('.nav-burger');

            // Check if the click was outside the menu and burger button
            if (burgerMenu && !burgerMenu.contains(e.target) && navBurger && !navBurger.contains(e.target)) {
                burgerMenu.style.display = 'none';
            }
        });
    });
}

// THEME TOGGLING (Dark / Light Mode)
function applyTheme(mode) {
    const body = document.body;
    const btn = document.getElementById('themeToggleBtn');
    const isDark = mode === 'dark';
    body.classList.toggle('dark-mode', isDark);
    if (btn) {
        btn.textContent = isDark ? '☀️' : '🌙';
        btn.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
        btn.setAttribute('title', isDark ? 'Switch to light mode' : 'Switch to dark mode');
        btn.setAttribute('aria-pressed', isDark ? 'true' : 'false');
    }
    localStorage.setItem('preferred-theme', mode);
    // Notify any page-specific scripts (e.g., charts) of theme change
    window.dispatchEvent(new CustomEvent('themechange', {detail: {mode}}));
}

function detectPreferredTheme() {
    const stored = localStorage.getItem('preferred-theme');
    if (stored === 'dark' || stored === 'light') return stored;
    // Fallback to system preference
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function toggleTheme() {
    const isCurrentlyDark = document.body.classList.contains('dark-mode');
    applyTheme(isCurrentlyDark ? 'light' : 'dark');
}

function initTheme() {
    const btn = document.getElementById('themeToggleBtn');
    if (btn && !btn.dataset.themeInitialized) {
        btn.addEventListener('click', toggleTheme);
        btn.dataset.themeInitialized = 'true';
    }
    applyTheme(detectPreferredTheme());
}

// Initialize theme after DOM ready if not already invoked explicitly
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        if (typeof initTheme === 'function') initTheme();
    });
} else {
    if (typeof initTheme === 'function') initTheme();
}

// Toast notification logic
function showToast(message, timeout = 3500) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('show');
    // Clear any old timer
    if (toast._hideTimer) clearTimeout(toast._hideTimer);
    toast._hideTimer = setTimeout(() => {
        toast.classList.remove('show');
    }, timeout);
}

// Enhance applyTheme to show toast
const _origApplyTheme = typeof applyTheme === 'function' ? applyTheme : null;
if (_origApplyTheme) {
    applyTheme = function (mode) { // override keeping previous behavior
        _origApplyTheme(mode);
        showToast(mode === 'dark' ? 'Dark mode enabled' : 'Light mode enabled');
    };
}

// Bind audio toggle button (CSP friendly) once DOM is ready
(function bindAudioToggle() {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindAudioToggle);
        return;
    }
    const btn = document.getElementById('audioToggleBtn');
    if (btn && !btn.dataset.bound) {
        btn.addEventListener('click', toggleAudio);
        btn.dataset.bound = 'true';
    }
})();
