# Laboratorio Web Endurecido

Material educativo de ciberseguridad: una página **estática y endurecida** (sin backend, sin
base de datos, sin scripts de terceros) que:

1. **Comprueba en vivo sus cabeceras de seguridad** leyendo la respuesta real del servidor.
2. **Explica las defensas** contra XSS, clickjacking, MIME sniffing, downgrade/MITM, inyección
   SQL/RCE, fuga de datos y DDoS.
3. Ofrece un **libro de visitas que neutraliza intentos de XSS**: cualquier HTML o JavaScript se
   muestra como texto plano (`textContent`, nunca `innerHTML`) y se guarda solo en el `localStorage`
   del visitante.

## Endurecimiento
- La CSP (`script-src 'self'`) impide que se ejecute cualquier script inline o inyectado; el JavaScript
  propio vive en `app.js`.
- En **GitHub Pages** se aplican vía `<meta>` la CSP y la política de referer. Las cabeceras que solo
  pueden enviarse desde el servidor (HSTS, X-Frame-Options, nosniff, Permissions-Policy, COOP) se
  incluyen en `_headers` y `netlify.toml`: al desplegar en **Netlify** o **Cloudflare Pages** se activan
  las siete y la comprobación en vivo las marca todas en verde.

Autor: Daniel Alejandro Casanova Rodriguez — Universidad Central, Ingeniería de Sistemas (Ciberseguridad).
