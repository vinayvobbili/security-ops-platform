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
    console.log('Toggle audio called - music:', !!music, 'icon:', !!icon, 'src:', music ? music.src : undefined, 'muted:', music ? music.muted : undefined);
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
    localStorage.setItem('music-current-time', String(music.currentTime));
    localStorage.setItem('music-muted', String(music.muted));
    localStorage.setItem('music-playing', String(!music.paused));
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
    var trigger = document.querySelector('.nav-burger');
    if (menu) {
        const willShow = (menu.style.display === 'none' || menu.style.display === '');
        menu.style.display = willShow ? 'block' : 'none';
        menu.setAttribute('aria-hidden', willShow ? 'false' : 'true');
        if (trigger) trigger.setAttribute('aria-expanded', willShow ? 'true' : 'false');
    }
}

// Initialize burger menu event handlers
function initBurgerMenu() {
    if (window.__burgerMenuInitialized) return; // guard against double-binding
    window.__burgerMenuInitialized = true;
    document.addEventListener('DOMContentLoaded', function () {
        var burgerMenu = document.getElementById('burgerMenu');
        var trigger = document.querySelector('.nav-burger');
        if (trigger && !trigger.hasAttribute('aria-expanded')) {
            trigger.setAttribute('aria-expanded', 'false');
        }
        if (burgerMenu) {
            burgerMenu.querySelectorAll('a').forEach(function (link) {
                link.addEventListener('click', function () {
                    burgerMenu.style.display = 'none';
                    burgerMenu.setAttribute('aria-hidden', 'true');
                    if (trigger) trigger.setAttribute('aria-expanded', 'false');
                });
            });
        }
        // Keyboard accessibility for trigger
        if (trigger && !trigger.__kbBound) {
            trigger.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    toggleMenu();
                }
            });
            trigger.__kbBound = true;
        }

        // Global ESC key handler to close menu
        if (!document.__burgerEscBound) {
            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape') {
                    if (burgerMenu && burgerMenu.style.display === 'block') {
                        burgerMenu.style.display = 'none';
                        burgerMenu.setAttribute('aria-hidden', 'true');
                        if (trigger) trigger.setAttribute('aria-expanded', 'false');
                    }
                }
            });
            document.__burgerEscBound = true;
        }

        // Click away to close menu
        if (!document.__burgerClickBound) {
            document.addEventListener('click', function (e) {
                var navBurger = document.querySelector('.nav-burger');
                if (burgerMenu && !burgerMenu.contains(e.target) && navBurger && !navBurger.contains(e.target)) {
                    if (burgerMenu.style.display === 'block') {
                        burgerMenu.style.display = 'none';
                        burgerMenu.setAttribute('aria-hidden', 'true');
                        if (trigger) trigger.setAttribute('aria-expanded', 'false');
                    }
                }
            });
            document.__burgerClickBound = true;
        }
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
    // Notify any page-specific scripts (e.g., charts) of theme change
    window.dispatchEvent(new CustomEvent('themechange', {detail: {mode}}));
}

function detectOSTheme() {
    // Always use OS/system preference
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
    // Always apply OS theme on page load
    applyTheme(detectOSTheme());
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

// Theme toast notifications disabled - user preference
// const _origApplyTheme = typeof applyTheme === 'function' ? applyTheme : null;
// if (_origApplyTheme) {
//     applyTheme = function (mode) { // override keeping previous behavior
//         _origApplyTheme(mode);
//         showToast(mode === 'dark' ? 'Dark mode enabled' : 'Light mode enabled');
//     };
// }

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

// Auto-initialize burger menu listeners if not already initialized elsewhere
if (typeof initBurgerMenu === 'function') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initBurgerMenu);
    } else {
        initBurgerMenu();
    }
}
