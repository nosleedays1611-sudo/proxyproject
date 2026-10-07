const $ = (s) => document.querySelector(s);
let token = sessionStorage.getItem("remote_admin_token") || "";
$("#token").value = token;

function headers(json = false) {
  const h = { Authorization: `Bearer ${token}` };
  if (json) h["Content-Type"] = "application/json";
  return h;
}

function fmt(ts) {
  if (!ts) return "sem validade";
  return new Date(ts * 1000).toLocaleString("pt-BR");
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;"
  })[c]);
}

async function api(path, options = {}) {
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function load() {
  if (!token) {
    $("#status").textContent = "Informe o token.";
    return;
  }

  try {
    const data = await api("/api/admin/clients", { headers: headers() });
    $("#freeze").checked = !!data.frozen;

    $("#clients").innerHTML = data.clients.map(c => `
      <article class="client">
        <div>
          <strong>${esc(c.ipv4)}</strong>
          <div class="muted">Validade: ${fmt(c.expires_at)}</div>
          <div class="muted">Profile: ${esc(c.active_profile)}</div>
        </div>
        <div class="switches inline">
          ${Object.entries(c.settings || {}).map(([k,v]) => `
            <label>
              <input type="checkbox"
                     data-ip="${esc(c.ipv4)}"
                     data-key="${esc(k)}"
                     ${v ? "checked" : ""}>
              ${esc(k)}
            </label>
          `).join("")}
        </div>
        <div class="actions">
          <button data-toggle="${esc(c.ipv4)}" data-enabled="${c.enabled ? "1" : "0"}">
            ${c.enabled ? "Desativar" : "Ativar"}
          </button>
          <button class="danger" data-delete="${esc(c.ipv4)}">Excluir</button>
        </div>
      </article>
    `).join("") || '<p class="muted">Nenhum cliente.</p>';

    $("#status").textContent = `${data.clients.length} cliente(s).`;
  } catch (e) {
    $("#status").textContent = `Erro: ${e.message}`;
  }
}

$("#saveToken").addEventListener("click", () => {
  token = $("#token").value.trim();
  sessionStorage.setItem("remote_admin_token", token);
  load();
});

$("#refresh").addEventListener("click", load);

$("#saveClient").addEventListener("click", async () => {
  try {
    const ipv4 = $("#ipv4").value.trim();
    const days = Number($("#days").value || 30);
    const expires_at = Math.floor(Date.now()/1000) + days * 86400;
    const settings = {};
    document.querySelectorAll("[data-setting]").forEach(el => {
      settings[el.dataset.setting] = el.checked;
    });

    await api("/api/admin/clients", {
      method: "POST",
      headers: headers(true),
      body: JSON.stringify({
        ipv4,
        enabled: $("#enabled").checked,
        expires_at,
        active_profile: $("#profile").value.trim() || "default",
        settings
      })
    });
    await load();
  } catch (e) {
    alert(e.message);
  }
});

$("#freeze").addEventListener("change", async (e) => {
  try {
    await api("/api/admin/freeze", {
      method: "POST",
      headers: headers(true),
      body: JSON.stringify({ frozen: e.target.checked })
    });
  } catch (err) {
    alert(err.message);
    e.target.checked = !e.target.checked;
  }
});

$("#clients").addEventListener("change", async (e) => {
  const el = e.target;
  if (!el.matches("[data-ip][data-key]")) return;

  try {
    await api(`/api/admin/clients/${encodeURIComponent(el.dataset.ip)}/settings`, {
      method: "PATCH",
      headers: headers(true),
      body: JSON.stringify({ settings: { [el.dataset.key]: el.checked } })
    });
  } catch (err) {
    alert(err.message);
    el.checked = !el.checked;
  }
});

$("#clients").addEventListener("click", async (e) => {
  const toggle = e.target.closest("[data-toggle]");
  const del = e.target.closest("[data-delete]");

  try {
    if (toggle) {
      const ip = toggle.dataset.toggle;
      const enabled = toggle.dataset.enabled !== "1";
      await api(`/api/admin/clients/${encodeURIComponent(ip)}`, {
        method: "PATCH",
        headers: headers(true),
        body: JSON.stringify({ enabled })
      });
      await load();
    }

    if (del) {
      const ip = del.dataset.delete;
      if (!confirm(`Excluir ${ip}?`)) return;
      await api(`/api/admin/clients/${encodeURIComponent(ip)}`, {
        method: "DELETE",
        headers: headers()
      });
      await load();
    }
  } catch (err) {
    alert(err.message);
  }
});

load();
