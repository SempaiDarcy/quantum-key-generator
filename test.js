import {
    cryptoNewSeed,
    cryptoExpandSeed,
    cryptoNewKeyPairFromSeed,
    cryptoSign,
    cryptoVerify
} from './quantum-crypto-lib';

export async function run() {
    const seed = cryptoNewSeed();
    const expanded = cryptoExpandSeed(seed);
    const keyPair = cryptoNewKeyPairFromSeed(expanded);
    const message = crypto.getRandomValues(new Uint8Array(32));
    const signature = cryptoSign(message, keyPair.privateKey);
    const isValid = cryptoVerify(message, signature, keyPair.publicKey);

    return {
        seedHex: Buffer.from(seed).toString('hex'),
        seedBytes: Array.from(seed),
        expandedHex: Buffer.from(expanded).toString('hex'),
        expandedBytes: Array.from(expanded),
        privateKeyLength: keyPair.privateKey.byteLength,
        publicKeyLength: keyPair.publicKey.byteLength,
        privateKeyHex: Buffer.from(keyPair.privateKey.slice(0, 32)).toString('hex'),
        publicKeyHex: Buffer.from(keyPair.publicKey.slice(0, 32)).toString('hex'),
        messageHex: Buffer.from(message).toString('hex'),
        signatureLength: signature.byteLength,
        signatureHex: Buffer.from(signature.slice(0, 32)).toString('hex'),
        isValid: isValid
    };
}
