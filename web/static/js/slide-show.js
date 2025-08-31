const slides = document.querySelector('.slides');
const dots = document.querySelectorAll('.nav-dot');
const pausePlayButton = document.getElementById('pausePlayButton');
let currentSlide = 0;
const totalSlides = document.querySelectorAll('.slides figure').length;
let intervalId; // Variable to store the interval ID

// Start the auto-slide when the page loads
window.addEventListener('load', initializeSlider);
window.addEventListener('resize', updateSlider); // Recalculate on window resize

function initializeSlider() {
    updateSlider(); // Set initial slide position
    playSlideshow(); // Start auto-sliding

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
    intervalId = setInterval(() => moveSlide(1), 5000);
}

function toggleSlideshow() {
    const srcFileName = pausePlayButton.src.split('/').pop(); // Extract filename
    const isSlideshowRunning = srcFileName === "pause-solid.svg";

    if (isSlideshowRunning) {
        clearInterval(intervalId);
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

    // Check if it's the last slide
    if (currentSlide === totalSlides - 1) {
        showConfetti();
    }

    updateSlider();
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

    // Use the common toggleAudio function - no need to override
});
