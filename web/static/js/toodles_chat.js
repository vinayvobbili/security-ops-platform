// Session ID for tracking conversation
const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

// User information (set after auth)
let userEmailLocal = '';
let userFullEmail = '';
let userName = '';

// Config loaded from server
let appConfig = null;

// Load config from server
async function loadConfig() {
    try {
        const response = await fetch('/api/config');
        appConfig = await response.json();
    } catch (error) {
        console.error('Failed to load config:', error);
        appConfig = { email_domain: 'example.com' }; // fallback
    }
}

// Available commands
const commands = [
    { id: 'create_x_ticket', label: '🎫 Create X Ticket', icon: '🎫' },
    { id: 'approved_testing', label: '🧪 Approved Testing', icon: '🧪' },
    { id: 'ioc_hunt', label: '🔍 IOC Hunt', icon: '🔍' },
    { id: 'threat_hunt', label: '🎯 Threat Hunt', icon: '🎯' },
    { id: 'oncall', label: '☎️ On-Call Info', icon: '☎️' }
];

// Handle authentication
async function submitAuth(event) {
    event.preventDefault();
    const emailLocal = document.getElementById('emailLocal').value.trim();
    const password = document.getElementById('password').value;
    const authError = document.getElementById('authError');

    if (!emailLocal) {
        authError.textContent = 'Please enter your email address';
        authError.style.display = 'block';
        return;
    }

    if (!password) {
        authError.textContent = 'Please enter the password';
        authError.style.display = 'block';
        return;
    }

    // Hide previous errors
    authError.style.display = 'none';

    try {
        // Ensure config is loaded
        if (!appConfig) await loadConfig();
        const emailDomain = appConfig.email_domain || 'example.com';

        // Send authentication request to backend
        const response = await fetch('/api/toodles/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: emailLocal + '@' + emailDomain,
                password: password
            })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Store user info
            userEmailLocal = emailLocal;
            userFullEmail = emailLocal + '@' + emailDomain;

            // Store email in localStorage for future sessions
            localStorage.setItem('toodlesUserEmail', userFullEmail);

            // Extract first name for personalization (e.g., "john.doe" -> "John")
            const nameParts = emailLocal.split('.');
            userName = nameParts[0].charAt(0).toUpperCase() + nameParts[0].slice(1);

            // Close auth modal
            document.getElementById('authModal').style.display = 'none';

            // Show welcome message
            showWelcomeMessage();
        } else {
            // Show error message
            authError.textContent = data.error || 'Authentication failed';
            authError.style.display = 'block';
        }
    } catch (error) {
        authError.textContent = 'Network error. Please try again.';
        authError.style.display = 'block';
        console.error('Auth error:', error);
    }
}

// Initialize chat - don't show welcome until authenticated
window.addEventListener('DOMContentLoaded', async () => {
    // Load config first
    await loadConfig();

    // Check if auth modal is visible (user not authenticated)
    const authModal = document.getElementById('authModal');
    if (authModal && authModal.style.display !== 'none') {
        // Auth modal is visible, waiting for user input
        // Auto-focus the email input field
        const emailInput = document.getElementById('emailLocal');
        if (emailInput) {
            emailInput.focus();
        }
    } else {
        // User is already authenticated, show welcome
        // Try to get email from session or localStorage
        const storedEmail = localStorage.getItem('toodlesUserEmail');
        if (storedEmail) {
            userEmailLocal = storedEmail.split('@')[0];
            userFullEmail = storedEmail;
            const nameParts = userEmailLocal.split('.');
            userName = nameParts[0].charAt(0).toUpperCase() + nameParts[0].slice(1);
            showWelcomeMessage();
        }
    }
});

function showWelcomeMessage() {
    addBotMessage(`Hello ${userName}, Here are my commands. Click one to begin!`, true);
}

function addBotMessage(text, showCommands = false) {
    const messagesDiv = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message bot';

    const avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    avatar.textContent = '🤖';

    const content = document.createElement('div');
    content.className = 'message-content';
    content.textContent = text;

    messageDiv.appendChild(avatar);
    messageDiv.appendChild(content);
    messagesDiv.appendChild(messageDiv);

    if (showCommands) {
        const buttonsDiv = document.createElement('div');
        buttonsDiv.className = 'command-buttons';

        commands.forEach(cmd => {
            const button = document.createElement('button');
            button.className = 'command-button';
            button.textContent = cmd.label;
            button.onclick = () => handleCommand(cmd.id, cmd.label);
            buttonsDiv.appendChild(button);
        });

        content.appendChild(buttonsDiv);
    }

    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function addUserMessage(text) {
    const messagesDiv = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message user';

    const content = document.createElement('div');
    content.className = 'message-content';
    content.textContent = text;

    const avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    avatar.textContent = '👤';

    messageDiv.appendChild(content);
    messageDiv.appendChild(avatar);
    messagesDiv.appendChild(messageDiv);

    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function handleCommand(commandId, commandLabel) {
    addUserMessage(commandLabel);

    switch(commandId) {
        case 'create_x_ticket':
            showCreateXTicketForm();
            break;
        case 'approved_testing':
            showApprovedTestingForm();
            break;
        case 'ioc_hunt':
            showIOCHuntForm();
            break;
        case 'threat_hunt':
            showThreatHuntForm();
            break;
        case 'oncall':
            fetchOnCallInfo();
            break;
    }
}

function showModal(title, content) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = content;
    document.getElementById('formModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('formModal').style.display = 'none';
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('formModal');
    if (event.target == modal) {
        closeModal();
    }
}

function showCreateXTicketForm() {
    const formHTML = `
        <form id="createXTicketForm" onsubmit="submitCreateXTicket(event)">
            <div class="form-group">
                <label for="title">Title *</label>
                <input type="text" id="title" name="title" required>
            </div>
            <div class="form-group">
                <label for="details">Details *</label>
                <textarea id="details" name="details" required></textarea>
            </div>
            <div class="form-group">
                <label for="detection_source">Detection Source *</label>
                <select id="detection_source" name="detection_source" required>
                    <option value="">Select an option</option>
                    <option value="Threat Hunt">Threat Hunt</option>
                    <option value="CrowdStrike Falcon">CrowdStrike Falcon</option>
                    <option value="Employee Reported">Employee Reported</option>
                    <option value="Recorded Future">Recorded Future</option>
                    <option value="Third Party">Third Party</option>
                    <option value="Abnormal Security">Abnormal Security</option>
                    <option value="Other">Other</option>
                </select>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button type="submit" class="btn btn-primary">Submit</button>
            </div>
        </form>
        <div class="loading" id="formLoading">
            <div class="spinner"></div>
            <p>Creating ticket...</p>
        </div>
    `;
    showModal('Create X Ticket', formHTML);
}

async function submitCreateXTicket(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    data.user_email = userFullEmail;
    data.user_name = userName;

    form.style.display = 'none';
    document.getElementById('formLoading').style.display = 'block';

    try {
        const response = await fetch('/api/toodles/create-x-ticket', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        const result = await response.json();
        closeModal();

        if (result.success) {
            addBotMessage(`${userName}, ${result.message}`);
        } else {
            addBotMessage(`Error: ${result.error}`);
        }

        setTimeout(() => addBotMessage('What else can I help you with?', true), 500);
    } catch (error) {
        closeModal();
        addBotMessage(`Error: ${error.message}`);
    }
}

function showApprovedTestingForm() {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowStr = tomorrow.toISOString().split('T')[0];

    const formHTML = `
        <form id="approvedTestingForm" onsubmit="submitApprovedTesting(event)">
            <div class="form-group">
                <label for="usernames">Username(s)</label>
                <input type="text" id="usernames" name="usernames" placeholder="Use , as separator">
            </div>
            <div class="form-group">
                <label for="tester_hosts">IP(s), Hostname(s) of Tester</label>
                <textarea id="tester_hosts" name="tester_hosts" placeholder="Use , as separator"></textarea>
            </div>
            <div class="form-group">
                <label for="targets">IP(s), Hostname(s) to be tested</label>
                <textarea id="targets" name="targets" placeholder="Use , as separator"></textarea>
            </div>
            <div class="form-group">
                <label for="description">Description</label>
                <textarea id="description" name="description"></textarea>
            </div>
            <div class="form-group">
                <label for="notes_scope">Notes/Scope</label>
                <input type="text" id="notes_scope" name="notes_scope">
            </div>
            <div class="form-group">
                <label for="keep_until">Keep until (defaults to tomorrow at 5 PM ET)</label>
                <input type="date" id="keep_until" name="keep_until" value="${tomorrowStr}">
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button type="submit" class="btn btn-primary">Submit</button>
            </div>
        </form>
        <div class="loading" id="formLoading">
            <div class="spinner"></div>
            <p>Submitting...</p>
        </div>
    `;
    showModal('Approved Testing', formHTML);
}

async function submitApprovedTesting(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    data.user_email = userFullEmail;
    data.user_name = userName;

    form.style.display = 'none';
    document.getElementById('formLoading').style.display = 'block';

    try {
        const response = await fetch('/api/toodles/approved-testing', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        const result = await response.json();
        closeModal();

        if (result.success) {
            addBotMessage(`${userName}, ${result.message}`);
        } else {
            addBotMessage(`Error: ${result.error}`);
        }

        setTimeout(() => addBotMessage('What else can I help you with?', true), 500);
    } catch (error) {
        closeModal();
        addBotMessage(`Error: ${error.message}`);
    }
}

function showIOCHuntForm() {
    const formHTML = `
        <form id="iocHuntForm" onsubmit="submitIOCHunt(event)">
            <div class="form-group">
                <label for="ioc_title">Title *</label>
                <input type="text" id="ioc_title" name="ioc_title" required>
            </div>
            <div class="form-group">
                <label for="iocs">IOCs *</label>
                <textarea id="iocs" name="iocs" placeholder="Domains/Email-Addresses/Files" required></textarea>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button type="submit" class="btn btn-primary">Submit</button>
            </div>
        </form>
        <div class="loading" id="formLoading">
            <div class="spinner"></div>
            <p>Creating IOC Hunt...</p>
        </div>
    `;
    showModal('IOC Hunt', formHTML);
}

async function submitIOCHunt(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    data.user_email = userFullEmail;
    data.user_name = userName;

    form.style.display = 'none';
    document.getElementById('formLoading').style.display = 'block';

    try {
        const response = await fetch('/api/toodles/ioc-hunt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        const result = await response.json();
        closeModal();

        if (result.success) {
            addBotMessage(`${userName}, ${result.message}`);
        } else {
            addBotMessage(`Error: ${result.error}`);
        }

        setTimeout(() => addBotMessage('What else can I help you with?', true), 500);
    } catch (error) {
        closeModal();
        addBotMessage(`Error: ${error.message}`);
    }
}

function showThreatHuntForm() {
    const formHTML = `
        <form id="threatHuntForm" onsubmit="submitThreatHunt(event)">
            <div class="form-group">
                <label for="threat_title">Hunt Title *</label>
                <input type="text" id="threat_title" name="threat_title" required>
            </div>
            <div class="form-group">
                <label for="threat_description">Hunt Description *</label>
                <textarea id="threat_description" name="threat_description" required></textarea>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button type="submit" class="btn btn-primary">Submit</button>
            </div>
        </form>
        <div class="loading" id="formLoading">
            <div class="spinner"></div>
            <p>Creating Threat Hunt...</p>
        </div>
    `;
    showModal('Threat Hunt', formHTML);
}

async function submitThreatHunt(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    data.user_email = userFullEmail;
    data.user_name = userName;

    form.style.display = 'none';
    document.getElementById('formLoading').style.display = 'block';

    try {
        const response = await fetch('/api/toodles/threat-hunt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        const result = await response.json();
        closeModal();

        if (result.success) {
            addBotMessage(`${userName}, ${result.message}`);
        } else {
            addBotMessage(`Error: ${result.error}`);
        }

        setTimeout(() => addBotMessage('What else can I help you with?', true), 500);
    } catch (error) {
        closeModal();
        addBotMessage(`Error: ${error.message}`);
    }
}

async function fetchOnCallInfo() {
    addBotMessage('Fetching on-call information...');

    try {
        const response = await fetch('/api/toodles/oncall');
        const result = await response.json();

        if (result.success) {
            const info = result.data;
            addBotMessage(`${userName}, the DnR On-call person is ${info.name} - ${info.email_address} - ${info.phone_number}`);
        } else {
            addBotMessage(`Error: ${result.error}`);
        }

        setTimeout(() => addBotMessage('What else can I help you with?', true), 500);
    } catch (error) {
        addBotMessage(`Error: ${error.message}`);
    }
}

// Clear chat functionality
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('clearChatButton').addEventListener('click', function() {
        if (confirm('Are you sure you want to clear the chat history?')) {
            // Clear all messages
            const messagesDiv = document.getElementById('chatMessages');
            messagesDiv.innerHTML = '';

            // Show welcome message again
            showWelcomeMessage();
        }
    });
});
