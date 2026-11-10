// Login page (issue #70): sends the access key, then opens the app, which
// the server now serves to this browser's session.
const form = document.getElementById('login-form');
const keyInput = document.getElementById('login-key');
const submit = document.getElementById('login-submit');
const errorBox = document.getElementById('login-error');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.textContent = '';
  submit.disabled = true;
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: keyInput.value.trim() }),
      credentials: 'same-origin',
    });
    if (res.ok) {
      window.location.replace('/');
      return;
    }
    errorBox.textContent = res.status === 429
      ? 'Too many failed attempts. Wait a minute, then try again.'
      : res.status === 401 ? 'That access key is not correct.' : `Login failed (${res.status}).`;
  } catch (err) {
    errorBox.textContent = `Couldn't reach MailBackup: ${err.message || err}`;
  } finally {
    submit.disabled = false;
  }
});
