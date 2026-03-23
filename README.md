# client-side-ctf

Este laboratorio simula un panel de administración corporativo con múltiples "gadgets" vulnerables diseñado para explorar vulnerabilidades de **Prototype Pollution** tanto en el cliente (navegador) como en el servidor (Node.js).
### Requisitos previos

- [Node.js](https://nodejs.org/) (Versión 14 o superior recomendada).    
- NPM (incluido con Node.js).
    
```
 npm install express cookie-parser
 node index.js  
```
    
    El servidor se levantará en `http://localhost:8081`.
    

---
## 🔍 Análisis de Vulnerabilidades (Sinks)

|**Componente**|**Tipo de Vulnerabilidad**|**Gadget / Sink**|
|---|---|---|
|**Frontend**|DOM XSS|`widgetSettings.template`|
|**Frontend**|Open Redirect|`config.logoutRedirect`|
|**Backend**|Auth Bypass|`authStatus.authenticated` en middleware|
|**Backend**|SSRF|`logOptions.hostname` en `/api/ticket`|
|**Backend**|**RCE**|`execFile` options en `/api/run`|

---
