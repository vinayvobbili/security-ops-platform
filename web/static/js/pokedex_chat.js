// Session management
let sessionId = localStorage.getItem('pokedex_session_id');
if (!sessionId) {
    sessionId = generateSessionId();
    localStorage.setItem('pokedex_session_id', sessionId);
}

function generateSessionId() {
    return 'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 15);
}

// Chat functionality
const messagesContainer = document.getElementById('chatMessages');
const messageInput = document.getElementById('messageInput');
const sendButton = document.getElementById('sendButton');
const statusBanner = document.getElementById('statusBanner');
const statusMessage = document.getElementById('statusMessage');
const statusDetails = document.getElementById('statusDetails');

// Bot readiness state
let isBotReady = false;
let previousBotReady = null; // Track previous state to detect changes
let isProcessing = false; // Track if a message is currently being processed

// Check bot status
async function checkBotStatus() {
    try {
        const response = await fetch('/api/pokedex-status');
        const data = await response.json();

        if (data.ready) {
            // Bot is ready
            const wasNotReady = isBotReady === false || previousBotReady === false;
            isBotReady = true;

            // Only show success banner if this is a state change (not ready -> ready)
            if (wasNotReady || previousBotReady === null) {
                statusBanner.className = 'status-banner success show';
                statusMessage.textContent = '✅ ' + data.message;
                statusDetails.innerHTML = '';

                // Auto-hide success banner after 3 seconds
                setTimeout(() => {
                    statusBanner.classList.remove('show');
                }, 3000);
            }

            // Enable input (unless currently processing a message)
            if (!isProcessing) {
                messageInput.disabled = false;
                sendButton.disabled = false;
            }
            messageInput.placeholder = 'Ask me anything...';

            previousBotReady = true;

        } else {
            // Bot is not ready
            isBotReady = false;
            previousBotReady = false;
            statusBanner.className = 'status-banner error show';
            statusMessage.textContent = '❌ ' + data.message;

            // Show instructions if available
            if (data.instructions && data.instructions.length > 0) {
                const instructionsList = data.instructions.map(i => `<li>• ${i}</li>`).join('');
                statusDetails.innerHTML = `<ul>${instructionsList}</ul>`;
            } else {
                statusDetails.innerHTML = '';
            }

            // Disable input
            messageInput.disabled = true;
            sendButton.disabled = true;
            messageInput.placeholder = 'Chat unavailable';
        }

    } catch (error) {
        console.error('Error checking bot status:', error);
        isBotReady = false;
        previousBotReady = false;
        statusBanner.className = 'status-banner error show';
        statusMessage.textContent = '❌ Unable to connect to chat service';
        statusDetails.innerHTML = '<ul><li>• Check that the web server is running</li></ul>';

        // Disable input
        messageInput.disabled = true;
        sendButton.disabled = true;
        messageInput.placeholder = 'Chat unavailable';
    }
}

// Load chat history from localStorage
function loadChatHistory() {
    const history = localStorage.getItem('pokedex_chat_history');
    if (history) {
        try {
            const messages = JSON.parse(history);

            // Filter messages older than 2 hours
            const twoHoursAgo = Date.now() - (2 * 60 * 60 * 1000);
            const recentMessages = messages.filter(msg => {
                const msgTime = new Date(msg.timestamp).getTime();
                return msgTime >= twoHoursAgo;
            });

            // Update localStorage with filtered messages
            if (recentMessages.length !== messages.length) {
                localStorage.setItem('pokedex_chat_history', JSON.stringify(recentMessages));
            }

            // Clear welcome message if history exists
            if (recentMessages.length > 0) {
                messagesContainer.innerHTML = '';
            }

            // Group messages by date and display with date headers
            let currentDate = null;
            recentMessages.forEach(msg => {
                const msgDate = new Date(msg.timestamp);
                const dateStr = msgDate.toLocaleDateString('en-US', {
                    weekday: 'long',
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                });

                // Add date header if date changed
                if (dateStr !== currentDate) {
                    currentDate = dateStr;
                    const dateHeader = document.createElement('div');
                    dateHeader.className = 'date-separator';
                    dateHeader.textContent = dateStr;
                    messagesContainer.appendChild(dateHeader);
                }

                appendMessage(msg.role, msg.content, false, msg.timestamp);
            });
            scrollToBottom();
        } catch (e) {
            console.error('Error loading chat history:', e);
        }
    }
}

// Save message to chat history
function saveChatHistory(role, content) {
    let history = [];
    const stored = localStorage.getItem('pokedex_chat_history');
    if (stored) {
        try {
            history = JSON.parse(stored);
        } catch (e) {
            console.error('Error parsing chat history:', e);
        }
    }
    history.push({role, content, timestamp: new Date().toISOString()});
    // Keep only last 50 messages
    if (history.length > 50) {
        history = history.slice(-50);
    }
    localStorage.setItem('pokedex_chat_history', JSON.stringify(history));
}

function appendMessage(role, content, save = true, timestamp = null) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${role}`;

    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';

    // Simple markdown rendering
    let formattedContent = content
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')  // Bold
        .replace(/\*(.+?)\*/g, '<em>$1</em>')  // Italic
        .replace(/`(.+?)`/g, '<code>$1</code>')  // Inline code
        .replace(/\n/g, '<br>');  // Line breaks

    contentDiv.innerHTML = formattedContent;

    const timeDiv = document.createElement('div');
    timeDiv.className = 'message-time';
    // Use provided timestamp or current time
    const messageTime = timestamp ? new Date(timestamp) : new Date();
    timeDiv.textContent = messageTime.toLocaleTimeString();

    contentDiv.appendChild(timeDiv);
    messageDiv.appendChild(contentDiv);
    messagesContainer.appendChild(messageDiv);

    scrollToBottom();

    if (save) {
        saveChatHistory(role, content);
    }
}

function showTypingIndicator() {
    const typingDiv = document.createElement('div');
    typingDiv.className = 'typing-indicator show';
    typingDiv.id = 'typingIndicator';
    typingDiv.innerHTML = '<span></span><span></span><span></span>';
    messagesContainer.appendChild(typingDiv);
    scrollToBottom();
}

function hideTypingIndicator() {
    const typingIndicator = document.getElementById('typingIndicator');
    if (typingIndicator) {
        typingIndicator.remove();
    }
}

function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.textContent = '❌ ' + message;
    messagesContainer.appendChild(errorDiv);
    scrollToBottom();

    setTimeout(() => {
        errorDiv.remove();
    }, 5000);
}

function scrollToBottom() {
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

async function sendMessage() {
    const message = messageInput.value.trim();
    if (!message) return;

    // Check if bot is ready
    if (!isBotReady) {
        showError('Chat is not available. Please check the status banner above.');
        return;
    }

    // Check if already processing a message
    if (isProcessing) {
        return;
    }

    // Set processing state and disable input
    isProcessing = true;
    messageInput.disabled = true;
    sendButton.disabled = true;

    // Display user message
    appendMessage('user', message);
    messageInput.value = '';

    // Create placeholder for streaming response
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message assistant';

    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.innerHTML = '<span class="streaming-cursor">▋</span>';

    messageDiv.appendChild(contentDiv);
    messagesContainer.appendChild(messageDiv);
    scrollToBottom();

    let fullResponse = '';

    try {
        const response = await fetch('/api/pokedex-chat-stream', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                message: message,
                session_id: sessionId
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();

        while (true) {
            const {done, value} = await reader.read();

            if (done) break;

            const chunk = decoder.decode(value);
            const lines = chunk.split('\n');

            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    try {
                        const data = JSON.parse(line.substring(6));

                        if (data.error) {
                            showError(data.error);
                            contentDiv.innerHTML = '❌ Error occurred';
                            break;
                        }

                        if (data.done) {
                            // Remove streaming cursor and add timestamp
                            const timeDiv = document.createElement('div');
                            timeDiv.className = 'message-time';
                            timeDiv.textContent = new Date().toLocaleTimeString();

                            // Format the final response with markdown
                            let formattedContent = fullResponse
                                .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
                                .replace(/\*(.+?)\*/g, '<em>$1</em>')
                                .replace(/`(.+?)`/g, '<code>$1</code>')
                                .replace(/\n/g, '<br>');

                            contentDiv.innerHTML = formattedContent;
                            contentDiv.appendChild(timeDiv);

                            // Save to history
                            saveChatHistory('assistant', fullResponse);
                            break;
                        }

                        if (data.token) {
                            fullResponse += data.token;

                            // Update display with streaming cursor
                            let displayContent = fullResponse
                                .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
                                .replace(/\*(.+?)\*/g, '<em>$1</em>')
                                .replace(/`(.+?)`/g, '<code>$1</code>')
                                .replace(/\n/g, '<br>');

                            contentDiv.innerHTML = displayContent + '<span class="streaming-cursor">▋</span>';
                            scrollToBottom();
                        }
                    } catch (e) {
                        console.error('Error parsing SSE data:', e);
                    }
                }
            }
        }

    } catch (error) {
        console.error('Error in streaming:', error);
        contentDiv.innerHTML = '❌ Failed to get response. Please try again.';
        showError('Streaming error occurred');
    } finally {
        // Clear processing state and re-enable input
        isProcessing = false;
        messageInput.disabled = false;
        sendButton.disabled = false;
        messageInput.focus();
    }
}

// Clear chat functionality
function clearChat() {
    if (confirm('Are you sure you want to clear the chat history? This cannot be undone.')) {
        // Clear localStorage
        localStorage.removeItem('pokedex_chat_history');

        // Clear messages container and show welcome message
        messagesContainer.innerHTML = `
                <div class="message assistant">
                    <div class="message-content">
                        <strong>Welcome to Pokedex!</strong> 🎉<br><br>
                        I'm your intelligent assistant, ready to help with security operations, threat hunting, and general questions.
                        <br><br>How can I assist you today?
                    </div>
                </div>
            `;

        // Focus input
        messageInput.focus();
    }
}

// Event listeners
sendButton.addEventListener('click', sendMessage);
messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

document.getElementById('clearChatButton').addEventListener('click', clearChat);

// Check bot status on page load
checkBotStatus();

// Periodic status check every 30 seconds
setInterval(checkBotStatus, 30000);

// Load chat history on page load
loadChatHistory();

// Focus input on load (only if bot is ready)
if (isBotReady) {
    messageInput.focus();
}

// Initialize audio player
if (typeof initRandomMusic === 'function') {
    initRandomMusic();
}
