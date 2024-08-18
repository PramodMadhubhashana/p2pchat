const socket = io();

const usernameInput = document.getElementById('username');
const messageInput = document.getElementById('message');
const sendButton = document.getElementById('send-button');
const chatMessages = document.getElementById('chat-messages');

function displayMessage(username, message) {
    const messageElement = document.createElement('div');
    messageElement.classList.add('chat-message');
    messageElement.innerHTML = `<span class="username">${username}:</span> ${message}`;
    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

if (sendButton) {
    sendButton.addEventListener('click', () => {
        const username = usernameInput.value.trim();
        const message = messageInput.value.trim();

        if (username === '' || message === '') {
            alert('Username and message cannot be empty.');
            return;
        }

        socket.emit('send_message', {
            username: username,
            message: message
        });

        messageInput.value = '';
    });
}

socket.on('display_message', (data) => {
    // Decrypt the message on the receiver side
    fetch('/decrypt_message', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            message: data.message,
            hash: data.hash
        })
    })
    .then(response => response.json())
    .then(decryptedData => {
        if (decryptedData.error) {
            alert(`Error: ${decryptedData.error}`);
        } else {
            displayMessage(data.username, decryptedData.message);
        }
    });
});

socket.on('error', (data) => {
    alert(`Error: ${data.error}`);
});
