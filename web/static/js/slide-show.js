const slides = document.querySelector('.slides');
const dots = document.querySelectorAll('.nav-dot');
const pausePlayButton = document.getElementById('pausePlayButton');
let timingProgressContainer;
let timingProgressBar;
let currentSlide = 0;
const totalSlides = document.querySelectorAll('.slides figure').length;
let intervalId; // Variable to store the interval ID
let progressIntervalId; // Variable to store the progress bar interval ID
let slideInterval = 5000; // Default: 5 seconds per slide (will be updated by speed control)

// Start the auto-slide when the page loads
window.addEventListener('load', initializeSlider);
window.addEventListener('resize', updateSlider); // Recalculate on window resize

function initializeSlider() {
    // Get progress bar elements after DOM is loaded
    timingProgressContainer = document.getElementById('timingProgressContainer2');
    timingProgressBar = document.getElementById('timingProgressBar2');
    
    updateSlider(); // Set initial slide position
    playSlideshow(); // Start auto-sliding
    initializeSpeedControl(); // Initialize speed control
    updateSpeedNeedle(slideInterval); // Set initial needle position

    // Add click event listeners to all slides
    document.querySelectorAll('.slides figure').forEach(slide => {
        slide.addEventListener('click', () => {
            toggleSlideshow();
        });
    });

    // Add click event listeners to navigation dots
    document.querySelectorAll('.nav-dot').forEach(dot => {
        dot.addEventListener('click', function () {
            const slideIndex = parseInt(this.getAttribute('data-slide-index'));
            goToSlide(slideIndex);
        });
    });
}

function playSlideshow() {
    intervalId = setInterval(() => {
        moveSlide(1);
    }, slideInterval);
    startProgressBar();
}

function startProgressBar() {
    if (!timingProgressBar) {
        return;
    }
    
    // Reset progress bar
    timingProgressBar.style.width = '0%';
    timingProgressContainer.classList.remove('paused');
    
    let progress = 0;
    const increment = 100 / (slideInterval / 50); // Update every 50ms
    
    progressIntervalId = setInterval(() => {
        progress += increment;
        if (progress >= 100) {
            progress = 100;
        }
        timingProgressBar.style.width = progress + '%';
        
        if (progress >= 100) {
            clearInterval(progressIntervalId);
        }
    }, 50);
}

function stopProgressBar() {
    if (progressIntervalId) {
        clearInterval(progressIntervalId);
        progressIntervalId = null;
    }
    timingProgressContainer.classList.add('paused');
}

function toggleSlideshow() {
    const srcFileName = pausePlayButton.src.split('/').pop(); // Extract filename
    const isSlideshowRunning = srcFileName === "pause-solid.svg";

    if (isSlideshowRunning) {
        clearInterval(intervalId);
        stopProgressBar();
        pausePlayButton.src = "/static/icons/play-solid.svg";
    } else {
        playSlideshow();
        pausePlayButton.src = "/static/icons/pause-solid.svg";
    }
}

// Move to a specific slide
function goToSlide(index) {
    currentSlide = index;
    updateSlider();
    // Restart progress bar if slideshow is running
    if (intervalId) {
        stopProgressBar();
        startProgressBar();
    }
}

// Initialize speed control
function initializeSpeedControl() {
    const speedOptions = document.querySelectorAll('.speed-option');
    speedOptions.forEach(option => {
        option.addEventListener('click', function() {
            const newSpeed = parseInt(this.dataset.speed);
            changeSlideSpeed(newSpeed);
            
            // Update active state
            speedOptions.forEach(opt => opt.classList.remove('active'));
            this.classList.add('active');
            
            // Close the menu
            document.getElementById('speedMenu').style.display = 'none';
        });
    });
}

// Change slideshow speed
function changeSlideSpeed(newInterval) {
    slideInterval = newInterval;
    
    // Update needle position based on speed
    updateSpeedNeedle(newInterval);
    
    // If slideshow is currently running, restart it with new speed
    if (intervalId) {
        clearInterval(intervalId);
        stopProgressBar();
        playSlideshow();
    }
}

// Update needle position based on current speed
function updateSpeedNeedle(speed) {
    const needle = document.querySelector('.needle');
    if (needle) {
        // Map speed to needle rotation (left to right across semi-circle)
        // 2000ms (fast) = -45deg, 5000ms (normal) = 0deg, 12000ms (very slow) = +45deg
        let rotation;
        if (speed <= 2000) rotation = -45;
        else if (speed <= 3000) rotation = -22.5;
        else if (speed <= 5000) rotation = 0;
        else if (speed <= 8000) rotation = 22.5;
        else rotation = 45;
        
        needle.style.transform = `rotate(${rotation}deg)`;
        needle.style.transformOrigin = '50px 50px';
    }
}


function showConfetti() {
    // Multiple bursts of confetti for a more exciting effect
    confetti({
        particleCount: 100, spread: 70, origin: {y: 0.6}
    });

    // Additional burst
    setTimeout(() => {
        confetti({
            particleCount: 100, spread: 100, origin: {y: 0.7}
        });
    }, 300);
}

function moveSlide(direction) {
    currentSlide += direction;

    // Wrap around logic
    if (currentSlide >= totalSlides) {
        currentSlide = 0;
    } else if (currentSlide < 0) {
        currentSlide = totalSlides - 1;
    }

    updateSlider();
    
    // Restart progress bar if slideshow is running
    if (intervalId) {
        stopProgressBar();
        startProgressBar();
    }

    // Check if we just moved to the last slide
    if (currentSlide === totalSlides - 1 && direction === 1) {
        setTimeout(() => showConfetti(), 100); // Small delay to ensure slide is visible
    }
}

function updateSlider() {
    const slideWidth = document.querySelector('.slider-container').clientWidth;
    slides.style.transform = `translateX(-${currentSlide * slideWidth}px)`;
    dots.forEach((dot, index) => {
        dot.classList.toggle('active', index === currentSlide);
    });

    if (currentSlide === 0) {
        document.body.classList.remove("show-background");
    } else {
        document.body.classList.add("show-background");
    }
}

// Initialize random music on page load
initRandomMusic();

function toggleMenu() {
    const menu = document.getElementById('burgerMenu');
    menu.style.display = (menu.style.display === 'none' || menu.style.display === '') ? 'block' : 'none';
}

function restartSlideshow() {
    currentSlide = 0;
    updateSlider();
    // If paused, also resume the slideshow
    if (pausePlayButton.src.split('/').pop() === "play-solid.svg") {
        playSlideshow();
        pausePlayButton.src = "/static/icons/pause-solid.svg";
    }
}

function toggleSpeedMenu() {
    const speedMenu = document.getElementById('speedMenu');
    speedMenu.style.display = speedMenu.style.display === 'none' ? 'block' : 'none';
}

document.addEventListener('DOMContentLoaded', () => {
    const music = document.getElementById('music');
    const music_icon = document.getElementById('music-icon');

    music.volume = 0.5; // Set initial volume (0.0 to 1.0)
    music.muted = true; // Ensure always starts muted
    music_icon.src = '/static/icons/volume-xmark-solid.svg'; // Ensure icon shows muted state

    // Add keyboard event listener for slideshow navigation
    document.addEventListener('keydown', function (event) {
        switch (event.code) {
            case 'ArrowLeft':
                event.preventDefault();
                moveSlide(-1);
                break;
            case 'ArrowRight':
                event.preventDefault();
                moveSlide(1);
                break;
            case 'Space':
                event.preventDefault();
                toggleSlideshow();
                break;
        }
    });

    // Close menu when a link is clicked
    const burgerMenu = document.getElementById('burgerMenu');
    if (burgerMenu) {
        burgerMenu.querySelectorAll('a').forEach(function (link) {
            link.addEventListener('click', function () {
                burgerMenu.style.display = 'none';
            });
        });
    }

    // Floating particle effect initialization
    const particles = document.getElementById('particles');
    if (particles) {
        for (let i = 0; i < 100; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = Math.random() * 100 + 'vw';
            particle.style.animationDelay = Math.random() * 6 + 's';
            particle.style.animationDuration = (Math.random() * 3 + 3) + 's';
            particle.style.opacity = Math.random() * 0.6 + 0.2;
            particles.appendChild(particle);
        }
    }
});

// Close burger menu when clicking outside
document.addEventListener('click', function (e) {
    const burgerMenu = document.getElementById('burgerMenu');
    const navBurger = document.querySelector('.nav-burger');
    const speedMenu = document.getElementById('speedMenu');
    const speedControl = document.getElementById('speedControl');

    // Check if the click was outside the menu and burger button
    if (burgerMenu && !burgerMenu.contains(e.target) && !navBurger.contains(e.target)) {
        burgerMenu.style.display = 'none';
    }

    // Close speed menu when clicking outside
    if (speedMenu && speedControl && !speedControl.contains(e.target)) {
        speedMenu.style.display = 'none';
    }
});

// Hide loading overlay after content is fully loaded
window.addEventListener('load', function () {
    const loadingOverlay = document.getElementById('loadingOverlay');
    if (loadingOverlay) {
        loadingOverlay.style.opacity = '0';
        setTimeout(function () {
            loadingOverlay.style.display = 'none';
        }, 500);
    }
});

