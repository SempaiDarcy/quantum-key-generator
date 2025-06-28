const crypto = require('./index.js');

// Генерация инициализационного значения (Seed)
const initValue = crypto.cryptoNewSeed();
console.log('\n===== Инициализационное значение (Seed) =====');
console.log('Инициализационное значение (шестнадцатеричный):', Buffer.from(initValue).toString('hex'));
console.log('Инициализационное значение (массив байт):', initValue);

// Расширение инициализационного значения
const expandedValue = crypto.cryptoExpandSeed(initValue);
console.log('\n===== Расширенное инициализационное значение =====');
console.log('Расширенное значение (шестнадцатеричный):', Buffer.from(expandedValue).toString('hex'));
console.log('Расширенное значение (массив байт):', expandedValue);

// Генерация ключевой пары
const keyPair = crypto.cryptoNewKeyPairFromSeed(expandedValue);
const privateKey = keyPair.getPrivateKey();
const publicKey = keyPair.getPublicKey();

console.log('\n===== Ключевая пара =====');
console.log('Длина приватного ключа:', privateKey.length, 'байт');
console.log('Длина публичного ключа:', publicKey.length, 'байт');
console.log('Приватный ключ (первые 32 байта, hex):', Buffer.from(privateKey.slice(0, 32)).toString('hex'));
console.log('Приватный ключ (первые 32 байта, массив):', privateKey.slice(0, 32));
console.log('Публичный ключ (первые 32 байта, hex):', Buffer.from(publicKey.slice(0, 32)).toString('hex'));
console.log('Публичный ключ (первые 32 байта, массив):', publicKey.slice(0, 32));

// Генерация случайного сообщения
const message = crypto.cryptoRandom(32);
console.log('\n===== Случайное сообщение =====');
console.log('Сообщение (hex):', Buffer.from(message).toString('hex'));
console.log('Сообщение (массив байт):', message);

// Создание цифровой подписи
const signature = crypto.cryptoSign(message, privateKey);
console.log('\n===== Цифровая подпись =====');
console.log('Длина подписи:', signature.length, 'байт');
console.log('Подпись (первые 32 байта, hex):', Buffer.from(signature.slice(0, 32)).toString('hex'));
console.log('Подпись (первые 32 байта, массив):', signature.slice(0, 32));

// Проверка цифровой подписи
const isValid = crypto.cryptoVerify(message, signature, publicKey);
console.log('\n===== Проверка подписи =====');
console.log('Подпись корректна?', isValid ? 'Да' : 'Нет');
