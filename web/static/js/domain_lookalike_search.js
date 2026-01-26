// Domain Lookalike Search JavaScript

(function() {
    'use strict';

    let allDomains = [];
    let filteredDomains = [];
    let messageRotationInterval = null;
    let currentMessageIndex = 0;
    let parkingEventSource = null;
    let parkedCount = 0;
    let parkingCheckedCount = 0;
    let totalToCheck = 0;
    let rfEnriched = false;
    let rfHighRiskCount = 0;

    // Fun and security-related scanning messages
    const scanningMessages = [
        'Analyzing domain mutations...',
        'Detecting typosquatting patterns...',
        'Checking for homograph attacks...',
        'Scanning character substitutions...',
        'Investigating phishing domains...',
        'Processing fuzzing algorithms...',
        'Hunting for imposters...',
        'Checking DNS records...',
        'Analyzing vowel swaps...',
        'Detecting bitsquatting...',
        'Searching for hyphenation tricks...',
        'Investigating omission attacks...',
        'Checking transposition patterns...',
        'Looking for suspicious domains...',
        'Analyzing brand variations...',
        'Detecting character repetition...',
        'Checking insertion patterns...',
        'Hunting for evil twins...',
        'Scanning subdomain variations...',
        'Investigating lookalike TLDs...',
        '🔍 Deep scanning in progress...',
        '🛡️ Protecting your brand...',
        '⚡ Processing permutations...',
        '🎯 Identifying threats...',
        '💚 Almost there...'
    ];

    // DOM Elements
    const searchForm = document.getElementById('searchForm');
    const domainInput = document.getElementById('domain');
    const registeredOnlyCheckbox = document.getElementById('registered_only');
    const includeMaliciousTldsCheckbox = document.getElementById('include_malicious_tlds');
    const spinner = document.getElementById('spinner');
    const spinnerText = spinner ? spinner.querySelector('.spinner-text') : null;
    const resultsContainer = document.getElementById('resultsContainer');
    const errorContainer = document.getElementById('errorContainer');
    const resultsTable = document.getElementById('resultsTable');
    const fuzzerFilter = document.getElementById('fuzzerFilter');
    const statusFilter = document.getElementById('statusFilter');
    const parkingFilter = document.getElementById('parkingFilter');
    const parkingFilterGroup = document.getElementById('parkingFilterGroup');
    const rfFilter = document.getElementById('rfFilter');
    const rfFilterGroup = document.getElementById('rfFilterGroup');
    const rfEnrichBtn = document.getElementById('rfEnrichBtn');
    const rfStatCard = document.getElementById('rfStatCard');
    const rfHighRiskCountEl = document.getElementById('rfHighRiskCount');
    const exportBtn = document.getElementById('exportBtn');
    const domainModal = document.getElementById('domainModal');
    const modalClose = domainModal.querySelector('.modal-close');

    // Stats elements
    const originalDomainEl = document.getElementById('originalDomain');
    const totalCountEl = document.getElementById('totalCount');
    const registeredCountEl = document.getElementById('registeredCount');
    const parkedCountEl = document.getElementById('parkedCount');

    // Form submission
    searchForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const domain = domainInput.value.trim();
        const registeredOnly = registeredOnlyCheckbox.checked;
        const includeMaliciousTlds = includeMaliciousTldsCheckbox.checked;

        if (!domain) {
            showError('Please enter a domain name');
            return;
        }

        performSearch(domain, registeredOnly, includeMaliciousTlds);
    });

    // Filter changes
    fuzzerFilter.addEventListener('change', applyFilters);
    statusFilter.addEventListener('change', applyFilters);
    parkingFilter.addEventListener('change', applyFilters);
    rfFilter.addEventListener('change', applyFilters);

    // Export button
    exportBtn.addEventListener('click', exportResults);

    // RF Enrich button
    rfEnrichBtn.addEventListener('click', startRfEnrichment);

    // Modal close
    modalClose.addEventListener('click', closeModal);
    window.addEventListener('click', function(e) {
        if (e.target === domainModal) {
            closeModal();
        }
    });

    // Perform domain search
    function performSearch(domain, registeredOnly, includeMaliciousTlds) {
        showSpinner();
        hideError();
        hideResults();
        closeParkingStream();
        parkedCount = 0;
        rfEnriched = false;
        rfHighRiskCount = 0;

        const url = '/api/domain-lookalikes?domain=' + encodeURIComponent(domain) +
                    '&registered_only=' + (registeredOnly ? 'true' : 'false') +
                    '&include_malicious_tlds=' + (includeMaliciousTlds ? 'true' : 'false');

        fetch(url)
            .then(response => response.json())
            .then(data => {
                hideSpinner();

                if (!data.success) {
                    showError(data.error || 'An error occurred while searching for lookalike domains');
                    return;
                }

                allDomains = data.domains || [];
                displayResults(data);
                populateFuzzerFilter();
                applyFilters();

                // Start streaming parking status for registered domains
                if (registeredOnly && data.registered_count > 0) {
                    startParkingStream();
                }
            })
            .catch(error => {
                hideSpinner();
                console.error('Search error:', error);
                showError('Network error: ' + error.message);
            });
    }

    // Start SSE stream for parking status
    function startParkingStream() {
        const registeredDomains = allDomains
            .filter(d => d.registered)
            .map(d => d.domain);

        if (registeredDomains.length === 0) return;

        // Reset counters
        parkingCheckedCount = 0;
        totalToCheck = registeredDomains.length;

        // Show parking status indicator and filter
        if (parkedCountEl) {
            parkedCountEl.textContent = '...';
            parkedCountEl.parentElement.style.display = 'block';
        }
        if (parkingFilterGroup) {
            parkingFilterGroup.style.display = 'block';
            parkingFilter.value = 'all';  // Reset filter
        }

        // Show the parking progress indicator
        const parkingIndicator = document.getElementById('parkingIndicator');
        const parkingProgress = document.getElementById('parkingProgress');
        if (parkingIndicator) {
            parkingIndicator.style.display = 'flex';
            if (parkingProgress) {
                parkingProgress.textContent = `0 / ${totalToCheck} checked`;
            }
        }

        const url = '/api/domain-lookalikes/parking?domains=' +
                    encodeURIComponent(registeredDomains.join(','));

        parkingEventSource = new EventSource(url);

        parkingEventSource.onmessage = function(event) {
            const data = JSON.parse(event.data);

            if (data.complete) {
                closeParkingStream();
                return;
            }

            // Update domain in allDomains
            const domain = allDomains.find(d => d.domain === data.domain);
            if (domain) {
                domain.parked = data.parked;
                parkingCheckedCount++;

                // Update progress indicator
                if (parkingProgress) {
                    parkingProgress.textContent = `${parkingCheckedCount} / ${totalToCheck} checked`;
                }

                if (data.parked === true) {
                    parkedCount++;
                    if (parkedCountEl) {
                        parkedCountEl.textContent = parkedCount;
                    }
                }

                // Update the badge in the UI
                updateParkingBadge(data.domain, data.parked);
            }
        };

        parkingEventSource.onerror = function(error) {
            console.error('Parking SSE error:', error);
            closeParkingStream();
        };
    }

    // Close parking SSE stream
    function closeParkingStream() {
        if (parkingEventSource) {
            parkingEventSource.close();
            parkingEventSource = null;
        }

        // Hide the parking progress indicator
        const parkingIndicator = document.getElementById('parkingIndicator');
        if (parkingIndicator) {
            parkingIndicator.style.display = 'none';
        }
    }

    // Start RF enrichment
    function startRfEnrichment() {
        const registeredDomains = allDomains
            .filter(d => d.registered)
            .map(d => d.domain);

        if (registeredDomains.length === 0) {
            alert('No registered domains to enrich');
            return;
        }

        // Disable button and show loading state
        if (rfEnrichBtn) {
            rfEnrichBtn.disabled = true;
            rfEnrichBtn.textContent = '🔄 Enriching...';
        }

        // Show RF indicator
        const rfIndicator = document.getElementById('rfIndicator');
        const rfProgress = document.getElementById('rfProgress');
        if (rfIndicator) {
            rfIndicator.style.display = 'flex';
            if (rfProgress) {
                rfProgress.textContent = `0 / ${registeredDomains.length} enriched`;
            }
        }

        // Call RF API
        const url = '/api/domain-lookalikes/rf-enrich?domains=' +
                    encodeURIComponent(registeredDomains.join(','));

        fetch(url)
            .then(response => response.json())
            .then(data => {
                // Hide indicator
                if (rfIndicator) {
                    rfIndicator.style.display = 'none';
                }

                if (!data.success) {
                    alert('RF Enrichment failed: ' + (data.error || 'Unknown error'));
                    if (rfEnrichBtn) {
                        rfEnrichBtn.disabled = false;
                        rfEnrichBtn.textContent = '🛡️ RF Enrich';
                    }
                    return;
                }

                // Apply results to allDomains
                const results = data.results || {};
                rfHighRiskCount = 0;

                allDomains.forEach(domain => {
                    const domainName = domain.domain.toLowerCase();
                    if (results[domainName]) {
                        domain.rf_risk_score = results[domainName].risk_score;
                        domain.rf_risk_level = results[domainName].risk_level;
                        domain.rf_rules = results[domainName].rules || [];
                        domain.rf_evidence_count = results[domainName].evidence_count || 0;

                        if (domain.rf_risk_score >= 65) {
                            rfHighRiskCount++;
                        }
                    } else {
                        domain.rf_risk_score = null;
                        domain.rf_risk_level = null;
                        domain.rf_rules = [];
                    }
                });

                rfEnriched = true;

                // Update UI
                if (rfStatCard) {
                    rfStatCard.style.display = 'block';
                }
                if (rfHighRiskCountEl) {
                    rfHighRiskCountEl.textContent = rfHighRiskCount;
                }
                if (rfFilterGroup) {
                    rfFilterGroup.style.display = 'block';
                }
                if (rfEnrichBtn) {
                    rfEnrichBtn.textContent = '✓ RF Enriched';
                    rfEnrichBtn.disabled = true;
                }
                if (rfProgress) {
                    rfProgress.textContent = `${data.domains_enriched} / ${registeredDomains.length} enriched`;
                }

                // Re-render cards with RF badges
                applyFilters();
            })
            .catch(error => {
                console.error('RF enrichment error:', error);

                // Hide indicator
                if (rfIndicator) {
                    rfIndicator.style.display = 'none';
                }

                alert('RF Enrichment failed: ' + error.message);
                if (rfEnrichBtn) {
                    rfEnrichBtn.disabled = false;
                    rfEnrichBtn.textContent = '🛡️ RF Enrich';
                }
            });
    }

    // Update parking badge for a specific domain
    function updateParkingBadge(domainName, parked) {
        // Find the domain card and update its badge
        const cards = document.querySelectorAll('.domain-card');
        cards.forEach(card => {
            const nameEl = card.querySelector('.domain-name');
            if (nameEl && nameEl.textContent === domainName) {
                const badges = card.querySelector('.domain-badges');
                if (badges) {
                    // Remove existing parking badge if any
                    const existingBadge = badges.querySelector('.badge.parked, .badge.active, .badge.unknown');
                    if (existingBadge) {
                        existingBadge.remove();
                    }

                    // Add new parking badge
                    const parkedBadge = document.createElement('span');
                    if (parked === true) {
                        parkedBadge.className = 'badge parked';
                        parkedBadge.textContent = '🅿️ Parked';
                    } else if (parked === false) {
                        parkedBadge.className = 'badge active';
                        parkedBadge.textContent = '🌐 Active';
                    } else {
                        parkedBadge.className = 'badge unknown';
                        parkedBadge.textContent = '❓ Unknown';
                    }

                    // Insert after status badge
                    const statusBadge = badges.querySelector('.badge.registered, .badge.unregistered');
                    if (statusBadge && statusBadge.nextSibling) {
                        badges.insertBefore(parkedBadge, statusBadge.nextSibling);
                    } else {
                        badges.appendChild(parkedBadge);
                    }
                }
            }
        });
    }

    // Display results
    function displayResults(data) {
        originalDomainEl.textContent = data.original_domain;
        totalCountEl.textContent = data.total_count;
        registeredCountEl.textContent = data.registered_count;

        // Hide parked count and filter initially - will be shown when parking stream starts
        if (parkedCountEl) {
            parkedCountEl.parentElement.style.display = 'none';
        }
        if (parkingFilterGroup) {
            parkingFilterGroup.style.display = 'none';
        }

        // Hide RF elements initially
        if (rfStatCard) {
            rfStatCard.style.display = 'none';
        }
        if (rfFilterGroup) {
            rfFilterGroup.style.display = 'none';
        }

        // Show RF Enrich button if there are registered domains
        if (rfEnrichBtn && data.registered_count > 0) {
            rfEnrichBtn.style.display = 'inline-flex';
            rfEnrichBtn.disabled = false;
            rfEnrichBtn.textContent = '🛡️ RF Enrich';
        } else if (rfEnrichBtn) {
            rfEnrichBtn.style.display = 'none';
        }

        resultsContainer.style.display = 'block';
    }

    // Populate fuzzer filter dropdown
    function populateFuzzerFilter() {
        const fuzzers = new Set();
        allDomains.forEach(domain => {
            if (domain.fuzzer) {
                fuzzers.add(domain.fuzzer);
            }
        });

        // Clear existing options except "All"
        fuzzerFilter.innerHTML = '<option value="all">All Techniques</option>';

        // Add fuzzer options sorted alphabetically
        Array.from(fuzzers).sort().forEach(fuzzer => {
            const option = document.createElement('option');
            option.value = fuzzer;
            option.textContent = formatFuzzerName(fuzzer);
            fuzzerFilter.appendChild(option);
        });
    }

    // Format fuzzer names for display
    function formatFuzzerName(fuzzer) {
        const names = {
            'addition': 'Addition',
            'bitsquatting': 'Bitsquatting',
            'homoglyph': 'Homoglyph',
            'hyphenation': 'Hyphenation',
            'insertion': 'Insertion',
            'omission': 'Omission',
            'repetition': 'Repetition',
            'replacement': 'Replacement',
            'subdomain': 'Subdomain',
            'transposition': 'Transposition',
            'various': 'Various',
            'vowel-swap': 'Vowel Swap',
            'tld-swap': 'TLD Swap'
        };
        return names[fuzzer] || fuzzer;
    }

    // Apply filters
    function applyFilters() {
        const fuzzer = fuzzerFilter.value;
        const status = statusFilter.value;
        const parking = parkingFilter.value;
        const rf = rfFilter.value;

        filteredDomains = allDomains.filter(domain => {
            // Fuzzer filter
            if (fuzzer !== 'all' && domain.fuzzer !== fuzzer) {
                return false;
            }

            // Status filter
            if (status === 'registered' && !domain.registered) {
                return false;
            }
            if (status === 'unregistered' && domain.registered) {
                return false;
            }

            // Parking filter
            if (parking !== 'all') {
                if (parking === 'parked' && domain.parked !== true) {
                    return false;
                }
                if (parking === 'active' && domain.parked !== false) {
                    return false;
                }
                if (parking === 'unknown' && domain.parked !== null && domain.parked !== undefined) {
                    return false;
                }
            }

            // RF Risk filter
            if (rf !== 'all' && rfEnriched) {
                const score = domain.rf_risk_score;
                if (score === null || score === undefined) {
                    return false;
                }
                if (rf === 'critical' && score < 90) {
                    return false;
                }
                if (rf === 'high' && score < 65) {
                    return false;
                }
                if (rf === 'medium' && (score < 25 || score >= 65)) {
                    return false;
                }
                if (rf === 'low' && score >= 25) {
                    return false;
                }
            }

            return true;
        });

        renderDomainCards();
    }

    // Render domain cards
    function renderDomainCards() {
        if (filteredDomains.length === 0) {
            resultsTable.innerHTML = '<div class="no-results">No domains match the current filters</div>';
            return;
        }

        resultsTable.innerHTML = '';

        filteredDomains.forEach(domain => {
            const card = createDomainCard(domain);
            resultsTable.appendChild(card);
        });
    }

    // Create individual domain card
    function createDomainCard(domain) {
        const card = document.createElement('div');
        card.className = 'domain-card ' + (domain.registered ? 'registered' : 'unregistered');

        const header = document.createElement('div');
        header.className = 'domain-header';

        const name = document.createElement('div');
        name.className = 'domain-name';
        name.textContent = domain.domain;

        const badges = document.createElement('div');
        badges.className = 'domain-badges';

        // Status badge
        const statusBadge = document.createElement('span');
        statusBadge.className = 'badge ' + (domain.registered ? 'registered' : 'unregistered');
        statusBadge.textContent = domain.registered ? 'Registered' : 'Unregistered';
        badges.appendChild(statusBadge);

        // Parked badge (only for registered domains with parking info)
        if (domain.registered && domain.parked !== undefined) {
            const parkedBadge = document.createElement('span');
            if (domain.parked === true) {
                parkedBadge.className = 'badge parked';
                parkedBadge.textContent = '🅿️ Parked';
            } else if (domain.parked === false) {
                parkedBadge.className = 'badge active';
                parkedBadge.textContent = '🌐 Active';
            } else {
                parkedBadge.className = 'badge unknown';
                parkedBadge.textContent = '❓ Unknown';
            }
            badges.appendChild(parkedBadge);
        }

        // Fuzzer badge
        if (domain.fuzzer) {
            const fuzzerBadge = document.createElement('span');
            fuzzerBadge.className = 'badge fuzzer';
            fuzzerBadge.textContent = formatFuzzerName(domain.fuzzer);
            badges.appendChild(fuzzerBadge);
        }

        // RF Risk badge (only if enriched)
        if (domain.rf_risk_score !== null && domain.rf_risk_score !== undefined) {
            const rfBadge = document.createElement('span');
            const score = domain.rf_risk_score;
            if (score >= 90) {
                rfBadge.className = 'badge rf-critical';
                rfBadge.textContent = `🔴 RF: ${score}`;
                rfBadge.title = 'Critical Risk - ' + (domain.rf_rules || []).join(', ');
            } else if (score >= 65) {
                rfBadge.className = 'badge rf-high';
                rfBadge.textContent = `🟠 RF: ${score}`;
                rfBadge.title = 'High Risk - ' + (domain.rf_rules || []).join(', ');
            } else if (score >= 25) {
                rfBadge.className = 'badge rf-medium';
                rfBadge.textContent = `🟡 RF: ${score}`;
                rfBadge.title = 'Medium Risk - ' + (domain.rf_rules || []).join(', ');
            } else {
                rfBadge.className = 'badge rf-low';
                rfBadge.textContent = `🟢 RF: ${score}`;
                const rules = domain.rf_rules || [];
                if (score === 0) {
                    rfBadge.title = 'Recorded Future Risk Score: 0 - No malicious activity observed in threat intelligence feeds';
                } else if (rules.length > 0) {
                    rfBadge.title = 'Low Risk - ' + rules.join(', ');
                } else {
                    rfBadge.title = `Recorded Future Risk Score: ${score}`;
                }
            }
            badges.appendChild(rfBadge);
        }

        header.appendChild(name);
        header.appendChild(badges);
        card.appendChild(header);

        // Domain details
        if (domain.registered) {
            const details = document.createElement('div');
            details.className = 'domain-details';

            if (domain.dns_a && domain.dns_a.length > 0) {
                details.appendChild(createDetailItem('A Records', domain.dns_a.join(', ')));
            }

            if (domain.dns_aaaa && domain.dns_aaaa.length > 0) {
                details.appendChild(createDetailItem('AAAA Records', domain.dns_aaaa.join(', ')));
            }

            if (domain.dns_mx && domain.dns_mx.length > 0) {
                details.appendChild(createDetailItem('MX Records', domain.dns_mx.join(', ')));
            }

            if (domain.dns_ns && domain.dns_ns.length > 0) {
                details.appendChild(createDetailItem('NS Records', domain.dns_ns.join(', ')));
            }

            if (domain.geoip) {
                details.appendChild(createDetailItem('GeoIP', domain.geoip));
            }

            // RF Rules (if available)
            if (domain.rf_rules && domain.rf_rules.length > 0) {
                details.appendChild(createDetailItem('RF Evidence', domain.rf_rules.join(', ')));
            }

            card.appendChild(details);
        }

        // Click handler for details
        card.addEventListener('click', function() {
            showDomainDetails(domain);
        });

        return card;
    }

    // Create detail item
    function createDetailItem(label, value) {
        const item = document.createElement('div');
        item.className = 'detail-item';

        const labelEl = document.createElement('div');
        labelEl.className = 'detail-label';
        labelEl.textContent = label;

        const valueEl = document.createElement('div');
        valueEl.className = 'detail-value';
        valueEl.textContent = value || 'N/A';

        item.appendChild(labelEl);
        item.appendChild(valueEl);

        return item;
    }

    // Show domain details in modal
    function showDomainDetails(domain) {
        const modalBody = document.getElementById('modalBody');
        modalBody.innerHTML = '<div class="modal-spinner">Loading WHOIS information...</div>';
        domainModal.style.display = 'flex';

        // Fetch WHOIS info
        fetch('/api/domain-whois?domain=' + encodeURIComponent(domain.domain))
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    modalBody.innerHTML = formatWhoisInfo(domain, data);
                } else {
                    modalBody.innerHTML = formatDomainInfo(domain) +
                        '<p style="color: #f56565; margin-top: 1rem;">WHOIS lookup failed: ' +
                        (data.error || 'Unknown error') + '</p>';
                }
            })
            .catch(error => {
                console.error('WHOIS error:', error);
                modalBody.innerHTML = formatDomainInfo(domain) +
                    '<p style="color: #f56565; margin-top: 1rem;">Failed to fetch WHOIS data</p>';
            });
    }

    // Format domain info
    function formatDomainInfo(domain) {
        let html = '<div style="margin-bottom: 1.5rem;">';
        html += '<h3 style="margin: 0 0 1rem 0; color: #2d3748;">' + domain.domain + '</h3>';
        html += '<div style="display: grid; gap: 1rem;">';
        html += '<div><strong>Technique:</strong> ' + formatFuzzerName(domain.fuzzer) + '</div>';
        html += '<div><strong>Status:</strong> ' + (domain.registered ? '✅ Registered' : '❌ Unregistered') + '</div>';

        if (domain.dns_a && domain.dns_a.length > 0) {
            html += '<div><strong>A Records:</strong> ' + domain.dns_a.join(', ') + '</div>';
        }
        if (domain.dns_mx && domain.dns_mx.length > 0) {
            html += '<div><strong>MX Records:</strong> ' + domain.dns_mx.join(', ') + '</div>';
        }
        if (domain.geoip) {
            html += '<div><strong>GeoIP:</strong> ' + domain.geoip + '</div>';
        }

        html += '</div></div>';
        return html;
    }

    // Format WHOIS info
    function formatWhoisInfo(domain, whoisData) {
        let html = formatDomainInfo(domain);
        html += '<hr style="margin: 1.5rem 0; border: none; border-top: 2px solid #e2e8f0;">';
        html += '<h4 style="margin: 0 0 1rem 0; color: #2d3748;">WHOIS Information</h4>';
        html += '<div style="display: grid; gap: 0.75rem; font-size: 0.95rem;">';
        html += '<div><strong>Registrar:</strong> ' + (whoisData.registrar || 'N/A') + '</div>';
        html += '<div><strong>Creation Date:</strong> ' + (whoisData.creation_date || 'N/A') + '</div>';
        html += '<div><strong>Expiration Date:</strong> ' + (whoisData.expiration_date || 'N/A') + '</div>';

        if (whoisData.name_servers && whoisData.name_servers.length > 0) {
            html += '<div><strong>Name Servers:</strong><br>' + whoisData.name_servers.join('<br>') + '</div>';
        }

        if (whoisData.status && whoisData.status.length > 0) {
            html += '<div><strong>Status:</strong><br>' + whoisData.status.join('<br>') + '</div>';
        }

        html += '</div>';
        return html;
    }

    // Close modal
    function closeModal() {
        domainModal.style.display = 'none';
    }

    // Export results as CSV
    function exportResults() {
        if (filteredDomains.length === 0) {
            alert('No results to export');
            return;
        }

        const csv = generateCSV(filteredDomains);
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'domain_lookalikes_' + originalDomainEl.textContent + '_' + Date.now() + '.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    // Generate CSV from domains
    function generateCSV(domains) {
        // Check if any domain has parking info or RF data
        const hasParking = domains.some(d => d.parked !== undefined);
        const hasRf = domains.some(d => d.rf_risk_score !== undefined && d.rf_risk_score !== null);

        const headers = ['Domain', 'Technique', 'Status'];
        if (hasParking) {
            headers.push('Parked');
        }
        if (hasRf) {
            headers.push('RF Risk Score', 'RF Risk Level', 'RF Evidence');
        }
        headers.push('A Records', 'MX Records', 'GeoIP');

        let csv = headers.join(',') + '\n';

        domains.forEach(domain => {
            const row = [
                escapeCsvValue(domain.domain),
                escapeCsvValue(formatFuzzerName(domain.fuzzer)),
                domain.registered ? 'Registered' : 'Unregistered'
            ];

            if (hasParking) {
                let parkedStatus = 'N/A';
                if (domain.parked === true) parkedStatus = 'Yes';
                else if (domain.parked === false) parkedStatus = 'No';
                else if (domain.parked === null) parkedStatus = 'Unknown';
                row.push(parkedStatus);
            }

            if (hasRf) {
                row.push(
                    domain.rf_risk_score !== null && domain.rf_risk_score !== undefined ? domain.rf_risk_score : 'N/A',
                    escapeCsvValue(domain.rf_risk_level || 'N/A'),
                    escapeCsvValue((domain.rf_rules || []).join('; '))
                );
            }

            row.push(
                escapeCsvValue((domain.dns_a || []).join('; ')),
                escapeCsvValue((domain.dns_mx || []).join('; ')),
                escapeCsvValue(domain.geoip || '')
            );

            csv += row.join(',') + '\n';
        });

        return csv;
    }

    // Escape CSV value
    function escapeCsvValue(value) {
        if (!value) return '""';
        const stringValue = String(value);
        if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
            return '"' + stringValue.replace(/"/g, '""') + '"';
        }
        return stringValue;
    }

    // Rotate scanning messages
    function rotateMessage() {
        if (spinnerText) {
            currentMessageIndex = (currentMessageIndex + 1) % scanningMessages.length;
            spinnerText.textContent = scanningMessages[currentMessageIndex];
        }
    }

    // Show/hide UI elements
    function showSpinner() {
        spinner.style.display = 'flex';

        // Start with a random message
        currentMessageIndex = Math.floor(Math.random() * scanningMessages.length);
        if (spinnerText) {
            spinnerText.textContent = scanningMessages[currentMessageIndex];
        }

        // Rotate messages every 2.5 seconds
        if (messageRotationInterval) {
            clearInterval(messageRotationInterval);
        }
        messageRotationInterval = setInterval(rotateMessage, 2500);
    }

    function hideSpinner() {
        spinner.style.display = 'none';

        // Stop rotating messages
        if (messageRotationInterval) {
            clearInterval(messageRotationInterval);
            messageRotationInterval = null;
        }
    }

    function showResults() {
        resultsContainer.style.display = 'block';
    }

    function hideResults() {
        resultsContainer.style.display = 'none';
    }

    function showError(message) {
        errorContainer.style.display = 'block';
        document.getElementById('errorMessage').textContent = message;
    }

    function hideError() {
        errorContainer.style.display = 'none';
    }

})();
