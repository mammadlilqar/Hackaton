

const usersDatabase = [
  { username: 'user', password: 'pa' },
  { username: 'user2', password: 'password2' },
  // Add more user objects as needed
];

function validateUser(username, password) {
  return usersDatabase.some(user => user.username === username && user.password === password);
}

function handleLogin() {
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const errorContainer = document.getElementById('errorContainer');

  const username = usernameInput.value;
  const password = passwordInput.value;

  if (validateUser(username, password)) {
    // Redirect to success page (change "success.html" to the actual success page)
    window.location.href = 'success.html';
  } else {
    // Display error message on the login form
    errorContainer.innerHTML = '<p class="error-message">Invalid username or password. Please try again.</p>';

    // Clear the username and password fields
    usernameInput.value = '';
    passwordInput.value = '';
  }
}

document.getElementById('loginBtn').addEventListener('click', function(event) {
  event.preventDefault();
  handleLogin();
});
