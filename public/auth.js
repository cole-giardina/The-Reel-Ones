const TOKEN_KEY = 'jwtToken';

function saveToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

function requireTokenOrRedirect() {
  const token = getToken();
  if (!token) {
    window.location.href = '/login.html';
    return null;
  }
  return token;
}

function attachLogout(buttonId = 'logoutBtn') {
  const btn = document.getElementById(buttonId);
  if (!btn) return;
  btn.addEventListener('click', () => {
    clearToken();
    window.location.href = '/login.html';
  });
}
