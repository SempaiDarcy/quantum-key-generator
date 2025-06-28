// index.js

// Загружаем модули Node.js для возможных операций с файлами и путями
var fs = require('fs');
const path = require('path');

// Загружаем нативный модуль гибридной криптографии
// Это скомпилированная библиотека, например, с Emscripten или C++ кодом
var hybridpqc = require('./hybrid-crypto-module.js');

// Классы ошибок для обработки разных ситуаций
// Ошибка генерации случайных данных
function CryptoRandomError () { }
CryptoRandomError.prototype = new Error();

// Ошибка некорректных аргументов
function InvalidArgumentsError () { }
InvalidArgumentsError.prototype = new Error();

// Ошибка при выполнении криптографической операции
function OperationFailedError () { }
OperationFailedError.prototype = new Error();

// Константы для контроля размеров ключей, seed и сообщений
const CRYPTO_OK = 0; // Код успешного выполнения
const CRYPTO_SEED_BYTES = 96; // Размер seed в байтах
const CRYPTO_EXPANDED_SEED_BYTES = 160; // Размер расширенного seed
const CRYPTO_MESSAGE_LEN = 32; // Размер сообщения
const CRYPTO_SECRETKEY_BYTES = 4064; // Размер секретного ключа
const CRYPTO_PUBLICKEY_BYTES = 1408; // Размер публичного ключа
const CRYPTO_COMPACT_SIGNATURE_BYTES = 2558; // Размер компактной подписи

// Класс для хранения пары ключей
class KeyPair {
  constructor(privateKey, publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  // Возвращает приватный ключ
  getPrivateKey() {
    return this.privateKey;
  }

  // Возвращает публичный ключ
  getPublicKey() {
    return this.publicKey;
  }
}

// Преобразует строку Base64 в Uint8Array
function base64ToBytes(base64) {
  const binString = atob(base64);
  return Uint8Array.from(binString, (m) => m.codePointAt(0));
}

// Преобразует Uint8Array в строку Base64
function bytesToBase64(bytes) {
  const binString = Array.from(bytes, (byte) =>
      String.fromCodePoint(byte)
  ).join("");
  return btoa(binString);
}

// Генерирует массив случайных байт заданного размера
function cryptoRandom(size) {
  let randPtr = hybridpqc._mem_alloc(size);
  let ret = hybridpqc._dp_randombytes(randPtr, size);
  if (ret !== CRYPTO_OK) {
    hybridpqc._mem_free(randPtr);
    throw new CryptoRandomError();
  }
  const randBuf = new Uint8Array(hybridpqc.HEAPU8.buffer, randPtr, size);
  const typedRandArray = new Uint8Array(size);
  for (let i = 0; i < randBuf.length; i++) {
    typedRandArray[i] = randBuf[i];
  }
  hybridpqc._mem_free(randPtr);
  return typedRandArray;
}

// Создаёт новый seed из случайных байтов
function cryptoNewSeed() {
  return cryptoRandom(CRYPTO_SEED_BYTES);
}

// Расширяет seed до расширенного формата (для генерации ключей)
function cryptoExpandSeed(seedArray) {
  if (seedArray == null || seedArray.length !== CRYPTO_SEED_BYTES) {
    throw new InvalidArgumentsError();
  }

  // Создаём буфер с seed
  const typedSeedArray = new Uint8Array(CRYPTO_SEED_BYTES);
  for (let i = 0; i < CRYPTO_SEED_BYTES; i++) {
    typedSeedArray[i] = seedArray[i];
  }
  const seedPtr = hybridpqc._mem_alloc(typedSeedArray.length);
  hybridpqc.HEAPU8.set(typedSeedArray, seedPtr);

  // Выделяем память под расширенный seed
  let expandedSeedPtr = hybridpqc._mem_alloc(CRYPTO_EXPANDED_SEED_BYTES);

  // Вызываем функцию расширения
  let ret = hybridpqc._dp_sign_seedexpander(seedPtr, expandedSeedPtr);
  if (ret !== CRYPTO_OK) {
    hybridpqc._mem_free(seedPtr);
    hybridpqc._mem_free(expandedSeedPtr);
    throw new OperationFailedError();
  }

  // Читаем результат
  const expandedSeedBuf = new Uint8Array(hybridpqc.HEAPU8.buffer, expandedSeedPtr, CRYPTO_EXPANDED_SEED_BYTES);
  const typedExpandedSeedArray = new Uint8Array(CRYPTO_EXPANDED_SEED_BYTES);
  for (let i = 0; i < CRYPTO_EXPANDED_SEED_BYTES; i++) {
    typedExpandedSeedArray[i] = expandedSeedBuf[i];
  }

  hybridpqc._mem_free(seedPtr);
  hybridpqc._mem_free(expandedSeedPtr);

  return typedExpandedSeedArray;
}

// Генерация новой пары ключей со случайным seed
function cryptoNewKeyPair() {
  let expandedSeedArray = cryptoRandom(CRYPTO_EXPANDED_SEED_BYTES);
  return cryptoNewKeyPairFromSeed(expandedSeedArray);
}

// Генерация пары ключей из заданного расширенного seed
function cryptoNewKeyPairFromSeed(expandedSeedArray) {
  if (expandedSeedArray.length !== CRYPTO_EXPANDED_SEED_BYTES) {
    throw new InvalidArgumentsError();
  }

  let pkPtr = hybridpqc._mem_alloc(CRYPTO_PUBLICKEY_BYTES);
  let skPtr = hybridpqc._mem_alloc(CRYPTO_SECRETKEY_BYTES);

  const typedSeedArray = new Uint8Array(CRYPTO_EXPANDED_SEED_BYTES);
  const seedPtr = hybridpqc._mem_alloc(typedSeedArray.length);
  for (let i = 0; i < expandedSeedArray.length; i++) {
    typedSeedArray[i] = expandedSeedArray[i];
  }
  hybridpqc.HEAPU8.set(typedSeedArray, seedPtr);

  let ret = hybridpqc._dp_sign_keypair_seed(pkPtr, skPtr, seedPtr);
  if (ret !== CRYPTO_OK) {
    hybridpqc._mem_free(seedPtr);
    hybridpqc._mem_free(skPtr);
    hybridpqc._mem_free(pkPtr);
    throw new OperationFailedError();
  }

  const skBuf = new Uint8Array(hybridpqc.HEAPU8.buffer, skPtr, CRYPTO_SECRETKEY_BYTES);
  const pkBuf = new Uint8Array(hybridpqc.HEAPU8.buffer, pkPtr, CRYPTO_PUBLICKEY_BYTES);
  const skArray = new Uint8Array(CRYPTO_SECRETKEY_BYTES);
  const pkArray = new Uint8Array(CRYPTO_PUBLICKEY_BYTES);

  for (let i = 0; i < CRYPTO_SECRETKEY_BYTES; i++) {
    skArray[i] = skBuf[i];
  }
  for (let i = 0; i < CRYPTO_PUBLICKEY_BYTES; i++) {
    pkArray[i] = pkBuf[i];
  }

  hybridpqc._mem_free(seedPtr);
  hybridpqc._mem_free(skPtr);
  hybridpqc._mem_free(pkPtr);

  return new KeyPair(skArray, pkArray);
}

// Подпись сообщения с помощью приватного ключа
function cryptoSign(messageArray, privateKeyArray) {
  if (messageArray == null || messageArray.length !== CRYPTO_MESSAGE_LEN || privateKeyArray == null || privateKeyArray.length !== CRYPTO_SECRETKEY_BYTES) {
    throw new InvalidArgumentsError();
  }

  let smPtr = hybridpqc._mem_alloc(CRYPTO_COMPACT_SIGNATURE_BYTES);
  let smlPtr = hybridpqc._mem_alloc_long_long(1 * BigUint64Array.BYTES_PER_ELEMENT);

  // Создаём буферы под сообщение и ключ
  const typedMsgArray = new Uint8Array(messageArray);
  const msgPtr = hybridpqc._mem_alloc(typedMsgArray.length);
  hybridpqc.HEAPU8.set(typedMsgArray, msgPtr);

  const typedSkArray = new Uint8Array(privateKeyArray);
  const skyPtr = hybridpqc._mem_alloc(typedSkArray.length);
  hybridpqc.HEAPU8.set(typedSkArray, skyPtr);

  // Вызываем функцию подписи
  let ret = hybridpqc._dp_sign(smPtr, smlPtr, msgPtr, typedMsgArray.length, skyPtr);
  if (ret !== CRYPTO_OK) {
    hybridpqc._mem_free(msgPtr);
    hybridpqc._mem_free(skyPtr);
    hybridpqc._mem_free(smlPtr);
    hybridpqc._mem_free(smPtr);
    throw new OperationFailedError();
  }

  // Проверяем размер подписи
  const sigLenBuf = new BigUint64Array(hybridpqc.HEAPU8.buffer, smlPtr, 1);
  if (sigLenBuf != BigInt(CRYPTO_COMPACT_SIGNATURE_BYTES)) {
    throw new InvalidArgumentsError();
  }

  // Копируем подпись
  const sigBuf = new Uint8Array(hybridpqc.HEAPU8.buffer, smPtr, sigLenBuf);
  const sigArray = new Uint8Array(CRYPTO_COMPACT_SIGNATURE_BYTES);
  for (let i = 0; i < CRYPTO_COMPACT_SIGNATURE_BYTES; i++) {
    sigArray[i] = sigBuf[i];
  }

  hybridpqc._mem_free(msgPtr);
  hybridpqc._mem_free(skyPtr);
  hybridpqc._mem_free(smlPtr);
  hybridpqc._mem_free(smPtr);

  return sigArray;
}

// Проверка подписи
function cryptoVerify(messageArray, sigArray, publicKeyArray) {
  if (messageArray == null || messageArray.length !== CRYPTO_MESSAGE_LEN ||
      sigArray == null || sigArray.length !== CRYPTO_COMPACT_SIGNATURE_BYTES ||
      publicKeyArray == null || publicKeyArray.length !== CRYPTO_PUBLICKEY_BYTES) {
    throw new InvalidArgumentsError();
  }

  const typedMsgArray = new Uint8Array(messageArray);
  const msgPtr = hybridpqc._mem_alloc(typedMsgArray.length);
  hybridpqc.HEAPU8.set(typedMsgArray, msgPtr);

  const typedSmArray = new Uint8Array(sigArray);
  const smPtr = hybridpqc._mem_alloc(typedSmArray.length);
  hybridpqc.HEAPU8.set(typedSmArray, smPtr);

  const typedPkArray = new Uint8Array(publicKeyArray);
  const pkyPtr = hybridpqc._mem_alloc(typedPkArray.length);
  hybridpqc.HEAPU8.set(typedPkArray, pkyPtr);

  let ret = hybridpqc._dp_sign_verify(
      msgPtr,
      typedMsgArray.length,
      smPtr,
      typedSmArray.length,
      pkyPtr
  );

  hybridpqc._mem_free(msgPtr);
  hybridpqc._mem_free(smPtr);
  hybridpqc._mem_free(pkyPtr);

  return ret === CRYPTO_OK;
}

// Экспортируем все функции модуля
module.exports = {
  cryptoRandom,
  cryptoNewSeed,
  cryptoExpandSeed,
  cryptoNewKeyPair,
  cryptoNewKeyPairFromSeed,
  cryptoSign,
  cryptoVerify
};
