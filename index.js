const express = require('express');
const http = require('http'); 
const path = require('path');
const cookieParser = require('cookie-parser'); // Necesario para leer cookies fácilmente

const app = express();
const PORT = 8081;

app.use(express.json());
app.use(cookieParser()); // Activamos el parse de cookies

// === MIDDLEWARE DE AUTENTICACIÓN (GADGET VULNERABLE) ===
const checkAuth = (req, res, next) => {
    // Definimos un objeto de verificación vacío
    const authStatus = {};

    // 1. Verificación Normal: ¿Existe la cookie?
    if (req.cookies && req.cookies.auth_session) {
        authStatus.authenticated = true;
    }

    // 2. GADGET: Si authStatus.authenticated no existe, JS sube al prototipo.
    // Si el servidor ha sido contaminado globalmente, 'authenticated' será true.
    if (authStatus.authenticated === true) {
        next();
    } else {
        res.status(403).send(`
            <div style="font-family:sans-serif; text-align:center; margin-top:50px;">
                <h1 style="color:#dc3545;">403 FORBIDDEN</h1>
                <p>BLEACH Security: No se ha detectado una cookie de sesión válida.</p>
                <a href="/">Volver al Login</a>
            </div>
        `);
    }
};

// Servimos archivos estáticos de forma selectiva
app.use('/assets', express.static(path.join(__dirname, 'public')));

// === RUTAS DEL FRONTEND ===

// Login (Punto de entrada, siempre accesible)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/ticket', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Rutas protegidas por el middleware checkAuth
app.get('/dashboard', checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/networking', checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'net.html'));
});

app.get('/auditor', checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'system.html'));
});


// === 1. LA FUNCIÓN VULNERABLE (Source del Backend) ===
function mergeConfigs(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            mergeConfigs(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// === 2. ENDPOINT DE LOGIN (Vulnerable a SSPP) ===
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    let userSession = {
        authenticated: false,
        role: "guest"
    };

    // VULNERABILIDAD: Contaminación global vía req.body
    mergeConfigs(userSession, req.body);

    // Lógica admin:admin
    if (username === 'admin' && password === 'admin') {
        userSession.authenticated = true;
    }

    // Bypass por isAdmin o authenticated heredado
    if (userSession.authenticated || userSession.isAdmin === true) {
        // Establecemos la cookie (da igual el valor)
        res.cookie('auth_session', 'BLEACH_7e787_TOKEN', { httpOnly: true });
        
        return res.json({ 
            success: true, 
            message: "Acceso concedido", 
            redirect: "/dashboard" 
        });
    } else {
        return res.status(401).json({ 
            success: false, 
            message: "Credenciales inválidas." 
        });
    }
});

// Necesitamos importar child_process
const { execFile } = require('child_process');

// === 4. EL ENDPOINT DE RCE (Sink de Ejecución) ===
// Este endpoint simula una utilidad para verificar el estado de los nodos
app.post('/api/run', checkAuth, (req, res) => {
    let runOptions = {}; // Objeto vacío vulnerable

    try {
        // El atacante puede contaminar el prototipo antes de llamar a este endpoint
        // O usar este merge si se permite pasar un cuerpo JSON
        mergeConfigs(runOptions, req.body);

        // Uso vulnerable de execFile:
        // Si el prototipo está contaminado con "shell", "env" o "argv0",
        // podemos forzar la ejecución de comandos arbitrarios.
        execFile('/usr/bin/uptime', [], runOptions, (error, stdout, stderr) => {
            if (error) {
                return res.status(500).json({ 
                    success: false, 
                    message: "Error en la ejecución", 
                    error: error.message 
                });
            }
            res.json({ 
                success: true, 
                output: stdout 
            });
        });
    } catch (e) {
        res.status(500).json({ message: "Error interno del sistema de ejecución." });
    }
});

// === 3. EL ENDPOINT DE TICKETS (Sink SSRF) ===
app.post('/api/ticket', (req, res) => {
    let auditConfig = {
        action: "new_ticket",
        status: "open"
    };

    try {
        mergeConfigs(auditConfig, req.body);
        
        const logOptions = {
            method: 'GET',
            path: `/audit-log?action=${auditConfig.action}&user=${auditConfig.empId || 'unknown'}`
        };

        console.log(`[!] Petición interna dirigida a: ${logOptions.hostname || 'localhost'}`);

        const ssrfRequest = http.request(logOptions, (response) => {
            response.on('data', () => {}); 
        });

        ssrfRequest.on('error', (e) => {
            console.error(`[-] Error SSRF: ${e.message}`);
        });

        ssrfRequest.end();

        res.json({ message: "Ticket registrado correctamente." });

    } catch (error) {
        res.status(500).json({ message: "Error interno." });
    }
});

app.listen(PORT, () => {
    console.log(`
    ==================================================
    🚀 BLEACH Enterprise Server - SECURE MODE
    ==================================================
    🚪 Login (Root):  http://localhost:${PORT}/
    📊 Dashboard:     http://localhost:${PORT}/dashboard
    📡 Networking:    http://localhost:${PORT}/networking
    🛡️ Auditor:       http://localhost:${PORT}/auditor
    ==================================================
    `);
});