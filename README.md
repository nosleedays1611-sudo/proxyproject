# REMOTE VPS Project

Base pronta para Ubuntu 24.04 em `/opt/remote`.

## Incluído

- `proxy.py`: sua source original, preservada.
- `proxy_config.py`: configuração local.
- `backend/app.py`: API Flask + SQLite.
- `site/`: painel web.
- `config/remote-api.service`: systemd da API.
- `config/remote-proxy.service`: systemd do proxy.
- `config/nginx.conf.template`: template do domínio.
- `scripts/install.sh`: instalação.
- `mrwanx_system/data/`: `allowed_ips.json` e `freeze_state.json`.

## Deploy

```bash
cd /opt/remote
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
openssl rand -hex 32
openssl rand -hex 32
```

Coloque as duas chaves geradas em `.env`.

Teste:

```bash
gunicorn --workers 2 --bind 127.0.0.1:8080 backend.app:app
curl http://127.0.0.1:8080/health
```

Serviços:

```bash
cp config/remote-api.service /etc/systemd/system/
cp config/remote-proxy.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now remote-api
systemctl enable --now remote-proxy
```

Logs:

```bash
journalctl -u remote-api -f
journalctl -u remote-proxy -f
```

Nginx:

1. Copie `config/nginx.conf.template` para `/etc/nginx/sites-available/remote`.
2. Troque `YOUR_DOMAIN`.
3. Ative o site e rode Certbot.

## Observação

O Remote gerencia autorização, IPv4, validade, perfil e switches por cliente.
A `proxy.py` original foi preservada neste pacote. O pacote não adiciona lógica
nova para alterar tráfego de serviços de terceiros.
