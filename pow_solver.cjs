const { Worker } = require('worker_threads');
const { webcrypto } = require('crypto');
const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = 8004;

function fetchUrl(url, proxy) {
    return new Promise((resolve, reject) => {
        const targetUrl = new URL(url);
        if (proxy && targetUrl.protocol === 'https:') {
            // HTTPS through HTTP proxy requires CONNECT tunnel
            const proxyUrl = new URL(proxy);
            const connectOpts = {
                hostname: proxyUrl.hostname,
                port: proxyUrl.port || 80,
                method: 'CONNECT',
                path: `${targetUrl.hostname}:443`,
                headers: { 'Host': `${targetUrl.hostname}:443` },
            };
            if (proxyUrl.username) {
                connectOpts.headers['Proxy-Authorization'] = 'Basic ' +
                    Buffer.from(`${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password)}`).toString('base64');
            }
            const connectReq = http.request(connectOpts);
            connectReq.on('connect', (res, socket) => {
                if (res.statusCode !== 200) {
                    socket.destroy();
                    return reject(new Error(`Proxy CONNECT failed: ${res.statusCode}`));
                }
                const tlsOpts = {
                    socket,
                    servername: targetUrl.hostname,
                    rejectUnauthorized: false,
                };
                const tls = require('tls');
                const tlsSocket = tls.connect(tlsOpts, () => {
                    const reqStr = `GET ${targetUrl.pathname}${targetUrl.search} HTTP/1.1\r\nHost: ${targetUrl.hostname}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`;
                    tlsSocket.write(reqStr);
                    let raw = '';
                    tlsSocket.on('data', chunk => raw += chunk.toString());
                    tlsSocket.on('end', () => {
                        const bodyStart = raw.indexOf('\r\n\r\n');
                        if (bodyStart === -1) return reject(new Error('No body in response'));
                        let body = raw.slice(bodyStart + 4);
                        // Handle chunked transfer encoding
                        const headerPart = raw.slice(0, bodyStart).toLowerCase();
                        if (headerPart.includes('transfer-encoding: chunked')) {
                            let decoded = '';
                            let pos = 0;
                            while (pos < body.length) {
                                const nl = body.indexOf('\r\n', pos);
                                if (nl === -1) break;
                                const chunkSize = parseInt(body.slice(pos, nl), 16);
                                if (isNaN(chunkSize) || chunkSize === 0) break;
                                decoded += body.slice(nl + 2, nl + 2 + chunkSize);
                                pos = nl + 2 + chunkSize + 2;
                            }
                            body = decoded;
                        }
                        resolve(body);
                    });
                });
                tlsSocket.on('error', reject);
            });
            connectReq.on('error', reject);
            connectReq.end();
        } else if (proxy) {
            // HTTP through HTTP proxy
            const proxyUrl = new URL(proxy);
            const options = {
                hostname: proxyUrl.hostname,
                port: proxyUrl.port,
                path: url,
                method: 'GET',
                headers: { 'Host': targetUrl.hostname, 'User-Agent': 'Mozilla/5.0' },
            };
            if (proxyUrl.username) {
                options.headers['Proxy-Authorization'] = 'Basic ' +
                    Buffer.from(`${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password)}`).toString('base64');
            }
            http.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve(data));
            }).on('error', reject).end();
        } else {
            // Direct HTTPS fetch
            const mod = targetUrl.protocol === 'https:' ? https : http;
            mod.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, rejectUnauthorized: false }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve(data));
            }).on('error', reject);
        }
    });
}

async function solvePoW(powSetup, proxy) {
    const seqCode = await fetchUrl(powSetup.sequence, proxy);
    if (!seqCode || seqCode.length < 100) {
        throw new Error(`Failed to download sequence JS (got ${seqCode ? seqCode.length : 0} chars)`);
    }

    const workerCode = `
const { parentPort, workerData } = require('worker_threads');
const { webcrypto } = require('crypto');

global.crypto = webcrypto;
global.self = global;
global.performance = { now: () => Date.now() };

let messageHandler = null;

global.postMessage = (msg) => {
    parentPort.postMessage(msg);
};

Object.defineProperty(global, 'onmessage', {
    set: (fn) => { messageHandler = fn; },
    get: () => messageHandler,
});

global.addEventListener = (event, fn) => {
    if (event === 'message') messageHandler = fn;
};

${seqCode}

const checkAndSend = () => {
    if (messageHandler) {
        messageHandler({ data: workerData.workMessage });
    } else {
        setTimeout(checkAndSend, 50);
    }
};
setTimeout(checkAndSend, 100);
`;
    const tmpFile = path.join('/tmp', `pow_worker_${Date.now()}.js`);
    fs.writeFileSync(tmpFile, workerCode);

    const workMessage = {
        type: 'start',
        data: {
            type: 1, // TARGET_HASH
            itimeout: powSetup.timeout || 75000,
            seed: powSetup.work_config.seed,
            startingNonce: powSetup.work_config.starting_nonce,
            targetHashData: powSetup.work_config.splits.map(s => ({
                targetHashData: s.target_hash
            }))
        }
    };

    return new Promise((resolve, reject) => {
        const worker = new Worker(tmpFile, { workerData: { workMessage } });
        const timeout = setTimeout(() => {
            worker.terminate();
            try { fs.unlinkSync(tmpFile); } catch(e) {}
            reject(new Error('PoW timeout'));
        }, (powSetup.timeout || 75000) + 5000);

        worker.on('message', (msg) => {
            if (msg.type === 'done') {
                clearTimeout(timeout);
                worker.terminate();
                try { fs.unlinkSync(tmpFile); } catch(e) {}
                const result = {
                    pow_token: powSetup.pow_token,
                    session_token: powSetup.session_token || '',
                    hash_rate: msg.data.hashRate,
                    execution_time: msg.data.time,
                    transform: msg.data.finalTransform,
                    result: msg.data.targetHashData.map(t => ({
                        target_hash: t.targetHash,
                        attempt_count: t.iterations
                    }))
                };
                resolve(result);
            } else if (msg.type === 'error') {
                clearTimeout(timeout);
                worker.terminate();
                try { fs.unlinkSync(tmpFile); } catch(e) {}
                reject(new Error(JSON.stringify(msg.data)));
            }
        });

        worker.on('error', (err) => {
            clearTimeout(timeout);
            try { fs.unlinkSync(tmpFile); } catch(e) {}
            reject(err);
        });
    });
}

const server = http.createServer(async (req, res) => {
    if (req.method === 'POST' && req.url === '/solve') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { pow_setup, session_token, proxy } = JSON.parse(body);
                pow_setup.session_token = session_token;
                const result = await solvePoW(pow_setup, proxy);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, result }));
            } catch (err) {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: err.message }));
            }
        });
    } else {
        res.writeHead(404);
        res.end('Not found');
    }
});

server.listen(PORT, () => {
    console.log(`PoW solver listening on port ${PORT}`);
});
