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

    // If the saved src points at a track that no longer exists, refetch once.
    let audioRetried = false;
    music.addEventListener('error', (e) => {
        console.error('Audio loading error:', e, 'Source:', music.src);
        if (audioRetried) return;
        audioRetried = true;
        localStorage.removeItem('music-src');
        sessionStorage.removeItem('music-session-id');
        fetch('/api/random-audio')
            .then(r => r.json())
            .then(data => {
                if (!data.filename) return;
                const newSrc = '/static/audio/' + data.filename;
                music.src = newSrc;
                localStorage.setItem('music-src', newSrc);
                sessionStorage.setItem('music-session-id', Date.now().toString());
                console.log('Recovered from stale audio src, new:', newSrc);
            })
            .catch(err => console.error('Audio retry failed:', err));
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

// THEME TOGGLING — three modes: 'light' | 'dark' | 'system'
// 'system' tracks OS preference live via matchMedia.
const THEME_ICONS = { light: '☀️', dark: '🌙', system: '🖥️' };

function detectOSTheme() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(mode) {
    if (mode !== 'light' && mode !== 'dark' && mode !== 'system') mode = 'system';
    const effective = mode === 'system' ? detectOSTheme() : mode;
    document.body.classList.toggle('dark-mode', effective === 'dark');

    // Reflect saved choice in the trigger icon and the menu's selected state
    const triggerIcon = document.getElementById('themeDdIcon');
    if (triggerIcon) triggerIcon.textContent = THEME_ICONS[mode];
    document.querySelectorAll('.theme-dd-opt').forEach(opt => {
        opt.classList.toggle('selected', opt.dataset.theme === mode);
        opt.setAttribute('aria-selected', opt.dataset.theme === mode ? 'true' : 'false');
    });

    // Notify page-specific scripts (e.g., charts) of the *effective* theme
    window.dispatchEvent(new CustomEvent('themechange', {detail: {mode, effective}}));
}

function initTheme() {
    const trigger = document.getElementById('themeDdTrigger');
    const menu    = document.getElementById('themeDdMenu');

    if (trigger && menu && !trigger.dataset.themeInitialized) {
        const closeMenu = () => {
            menu.hidden = true;
            trigger.setAttribute('aria-expanded', 'false');
        };
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const willOpen = menu.hidden;
            menu.hidden = !willOpen;
            trigger.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
        });
        document.addEventListener('click', (e) => {
            if (menu.hidden) return;
            if (!menu.contains(e.target) && e.target !== trigger && !trigger.contains(e.target)) {
                closeMenu();
            }
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !menu.hidden) closeMenu();
        });
        menu.querySelectorAll('.theme-dd-opt').forEach(opt => {
            opt.addEventListener('click', () => {
                const mode = opt.dataset.theme;
                localStorage.setItem('theme', mode);
                applyTheme(mode);
                closeMenu();
            });
        });
        trigger.dataset.themeInitialized = 'true';
    }

    // Saved preference wins; default to 'system' if nothing saved.
    const saved = localStorage.getItem('theme') || 'system';
    applyTheme(saved);

    // Track OS theme changes live so 'system' reflects them without a reload.
    const mql = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)');
    if (mql && !mql.__irThemeBound) {
        const handler = () => {
            const cur = localStorage.getItem('theme') || 'system';
            if (cur === 'system') applyTheme('system');
        };
        if (mql.addEventListener) mql.addEventListener('change', handler);
        else if (mql.addListener) mql.addListener(handler);
        mql.__irThemeBound = true;
    }
}

function initPersonDropdown() {
    const trigger = document.getElementById('personDdTrigger');
    const menu    = document.getElementById('personDdMenu');
    if (!trigger || !menu || trigger.dataset.personInitialized) return;
    const closeMenu = () => {
        menu.hidden = true;
        trigger.setAttribute('aria-expanded', 'false');
    };
    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const willOpen = menu.hidden;
        menu.hidden = !willOpen;
        trigger.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
    });
    document.addEventListener('click', (e) => {
        if (menu.hidden) return;
        if (!menu.contains(e.target) && e.target !== trigger && !trigger.contains(e.target)) {
            closeMenu();
        }
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !menu.hidden) closeMenu();
    });
    trigger.dataset.personInitialized = 'true';
}

// Initialize theme after DOM ready if not already invoked explicitly
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        if (typeof initTheme === 'function') initTheme();
        if (typeof initPersonDropdown === 'function') initPersonDropdown();
    });
} else {
    if (typeof initTheme === 'function') initTheme();
    if (typeof initPersonDropdown === 'function') initPersonDropdown();
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

// Pick a new random track. Keeps playing if it was already unmuted.
async function skipAudio() {
    const music = document.getElementById('music');
    if (!music) return;
    const wasPlaying = !music.muted && !music.paused;
    try {
        const response = await fetch('/api/random-audio');
        const data = await response.json();
        if (!data.filename) return;
        const newSrc = '/static/audio/' + data.filename;
        music.src = newSrc;
        localStorage.setItem('music-src', newSrc);
        sessionStorage.setItem('music-session-id', Date.now().toString());
        localStorage.setItem('music-current-time', '0');
        if (wasPlaying) {
            music.play().catch(e => console.error('Skip play failed:', e));
        }
        console.log('Skipped to new audio:', newSrc);
    } catch (e) {
        console.error('Failed to skip audio:', e);
    }
}

// Bind audio toggle + skip buttons (CSP friendly) once DOM is ready
(function bindAudioButtons() {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindAudioButtons);
        return;
    }
    const toggleBtn = document.getElementById('audioToggleBtn');
    if (toggleBtn && !toggleBtn.dataset.bound) {
        toggleBtn.addEventListener('click', toggleAudio);
        toggleBtn.dataset.bound = 'true';
    }
    const skipBtn = document.getElementById('audioSkipBtn');
    if (skipBtn && !skipBtn.dataset.bound) {
        skipBtn.addEventListener('click', skipAudio);
        skipBtn.dataset.bound = 'true';
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

// ── Edit Auth ──
// Edit endpoints (contacts, docs, wiki, favorites…) now gate on the
// session cookie — any signed-in user is allowed. editFetch is a thin
// wrapper over fetch() kept so per-page JS doesn't have to be rewritten.
async function editFetch(url, options) {
    return fetch(url, options || {});
}
