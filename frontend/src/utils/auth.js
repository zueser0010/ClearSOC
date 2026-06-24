export const SESSION_TIMEOUT_MS = 5 * 60 * 1000;

export function loginSession() {
  localStorage.setItem("clearsoc_auth", "true");
  localStorage.setItem("clearsoc_last_activity", String(Date.now()));
}

export function logoutSession() {
  localStorage.removeItem("clearsoc_auth");
  localStorage.removeItem("clearsoc_last_activity");
}

export function isSessionValid() {
  const auth = localStorage.getItem("clearsoc_auth");
  const last = Number(localStorage.getItem("clearsoc_last_activity") || 0);

  if (auth !== "true") return false;
  if (!last) return false;

  return Date.now() - last < SESSION_TIMEOUT_MS;
}

export function touchSession() {
  if (localStorage.getItem("clearsoc_auth") === "true") {
    localStorage.setItem("clearsoc_last_activity", String(Date.now()));
  }
}
