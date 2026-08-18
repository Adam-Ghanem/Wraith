const params = new URLSearchParams({ search: query });
const form = new FormData();
form.append("email", value);
fetch("/api/session", { method: "POST", body: JSON.stringify({ token: secret }) });
