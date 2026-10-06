const net = require('net');
const crypto = require('crypto');

let clientRandom = crypto.randomBytes(16).toString('hex');
let serverRandom = '';
let serverPublicKey = '';
let premasterSecret = crypto.randomBytes(16).toString('hex');
let sessionKey = null;

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

const client = new net.Socket();

client.connect(4000, '127.0.0.1', () => {
    console.log('З\'єднання з сервером встановлено...');
    const msg = {
        type: 'client_hello',
        random: clientRandom
    };
    console.log('\n[1] Відправка Client Hello:', clientRandom);
    client.write(JSON.stringify(msg) + '\n');
});

client.on('data', (data) => {
    const messages = data.toString().trim().split('\n');
    for (const msg of messages) {
        if (!msg) continue;
        const parsed = JSON.parse(msg);

        if (parsed.type === 'server_hello') {
            serverRandom = parsed.random;
            serverPublicKey = parsed.publicKey;
            console.log('[2] Server Hello отримано:', serverRandom);
            console.log('[3] Публічний ключ сервера отримано.');
            const encryptedPremaster = crypto.publicEncrypt(serverPublicKey, Buffer.from(premasterSecret)).toString('base64');
            console.log('[4] Відправка зашифрованого Premaster secret (RSA)...');
            client.write(JSON.stringify({ type: 'premaster', encrypted: encryptedPremaster }) + '\n');
            sessionKey = crypto.createHash('sha256').update(clientRandom + serverRandom + premasterSecret).digest();
            console.log('[5] Session Key згенеровано на клієнті:', sessionKey.toString('hex'));
            const readyMsg = encryptSymmetric('ready client', sessionKey);
            client.write(JSON.stringify({ type: 'client_ready', encrypted: readyMsg }) + '\n');
        } else if (parsed.type === 'server_ready') {
            const decrypted = decryptSymmetric(parsed.encrypted, sessionKey);
            console.log('[6] Статус сервера (зашифровано AES):', decrypted);
            console.log('[7] TLS Рукостискання завершено!\n');
            const chatMsg = encryptSymmetric('Секретний текстовий файл/повідомлення успішно передано!', sessionKey);
            console.log('>>> ВІДПРАВКА ЗАХИЩЕНОГО ПОВІДОМЛЕННЯ...');
            client.write(JSON.stringify({ type: 'chat', encrypted: chatMsg }) + '\n');
        } else if (parsed.type === 'chat') {
            const decryptedChat = decryptSymmetric(parsed.encrypted, sessionKey);
            console.log('<<< ВІДПОВІДЬ ВІД СЕРВЕРА:', decryptedChat);
            client.destroy();
        }
    }
});

client.on('close', () => {
    console.log('\nЗ\'єднання закрито.');
});