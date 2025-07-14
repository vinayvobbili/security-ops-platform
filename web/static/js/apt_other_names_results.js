// JS for APT Other Names Results Page
// Currently, this script just focuses the input on page load.
document.addEventListener('DOMContentLoaded', function() {
    var input = document.getElementById('common_name');
    if (input) {
        input.focus();
    }
    // Animate results if present on load
    var results = document.getElementById('results');
    if (results) {
        setTimeout(function() {
            results.classList.add('visible');
        }, 200);
    }
});

// Animate button and spinner on submit
var searchForm = document.getElementById('searchForm');
if (searchForm) {
    searchForm.addEventListener('submit', function(e) {
        var btn = searchForm.querySelector('button[type="submit"]');
        if (btn) {
            btn.classList.add('pulse');
            setTimeout(function() { btn.classList.remove('pulse'); }, 400);
        }
        var spinner = document.getElementById('spinner');
        if (spinner) {
            spinner.style.display = 'inline-block';
        }
    });
}
// If results are dynamically loaded, call: document.getElementById('results').classList.add('visible');
