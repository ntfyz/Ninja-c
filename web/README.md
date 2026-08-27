# Ninja cPanel key manager

1. Upload the contents of `web/` to an HTTPS directory in `public_html`.
2. Copy `config.example.php` to `config.php` and set an absolute SQLite path outside
   `public_html` whenever the hosting account permits it.
3. Generate `admin_password_hash` with PHP `password_hash` as shown in the config.
4. Open `/admin/` to create, extend, disable, delete keys, or clear their HWID.
5. The app login endpoint is `/ninja_ios_v2/api/v1/auth/login/` and accepts the existing
   JSON fields `username`, `password`, and `device_id`.

Required PHP extensions: PDO SQLite, session, JSON. HTTPS is required because credentials
are submitted to the endpoint.
