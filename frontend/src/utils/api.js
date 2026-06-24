export const API_BASE = "http://localhost:8001";

export async function fetchAPI(endpoint, defaultValue = []) {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error(`API error ${endpoint}:`, err);
    return defaultValue;
  }
}
