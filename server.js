const net = require('net');
const crypto = require('crypto');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function encryptSymmetric(text, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decryptSymmetric(encryptedData, key) {
    const parts = encryptedData.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(parts[1], 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

const server = net.createServer((socket) => {
    let clientRandom = '';
    let serverRandom = crypto.randomBytes(16).toString('hex');
    let sessionKey = null;

    socket.on('data', (data) => {
        const messages = data.toString().trim().split('\n');
        for (const msg of messages) {
            if (!msg) continue;
            const parsed = JSON.parse(msg);

            if (parsed.type === 'client_hello') {
                clientRandom = parsed.random;
                console.log('\n[1] Client Hello отримано:', clientRandom);
                const response = {
                    type: 'server_hello',
                    random: serverRandom,
                    publicKey: publicKey
                };
                console.log('[2] Відправка Server Hello та Public Key...');
                socket.write(JSON.stringify(response) + '\n');
            } else if (parsed.type === 'premaster') {
                const premasterSecret = crypto.privateDecrypt(privateKey, Buffer.from(parsed.encrypted, 'base64')).toString('utf8');
                console.log('[4] Premaster secret розшифровано (RSA):', premasterSecret);
                sessionKey = crypto.createHash('sha256').update(clientRandom + serverRandom + premasterSecret).digest();
                console.log('[5] Session Key згенеровано на сервері:', sessionKey.toString('hex'));
            } else if (parsed.type === 'client_ready') {
                const decrypted = decryptSymmetric(parsed.encrypted, sessionKey);
                console.log('[6] Статус клієнта (зашифровано AES):', decrypted);
                const readyMsg = encryptSymmetric('ready server', sessionKey);
                socket.write(JSON.stringify({ type: 'server_ready', encrypted: readyMsg }) + '\n');
                console.log('[7] TLS Рукостискання завершено!\n');
            } else if (parsed.type === 'chat') {
                const decryptedChat = decryptSymmetric(parsed.encrypted, sessionKey);
                console.log('>>> ЗАХИЩЕНЕ ПОВІДОМЛЕННЯ ВІД КЛІЄНТА:', decryptedChat);
                const reply = encryptSymmetric('Привіт! Дані отримано і розшифровано. Канал надійно захищено.', sessionKey);
                socket.write(JSON.stringify({ type: 'chat', encrypted: reply }) + '\n');
            }
        }
    });
});

server.listen(4000, () => {
    console.log('TLS Сервер запущено на порту 4000. Очікування клієнта...');
});