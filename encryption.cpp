#include <iostream>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/rsa.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

int main() {
    using namespace CryptoPP;

    // Contraseña en texto plano
    std::string password = "PASSWORD";

    // Calcular el hash SHA-256
    SHA256 sha256;
    byte digest[SHA256::DIGESTSIZE];
    sha256.CalculateDigest(digest, (const byte*)password.c_str(), password.size());

    // Convertir el hash a hexadecimal para mostrarlo
    HexEncoder encoder;
    std::string hashHex;
    encoder.Attach(new StringSink(hashHex));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();
    std::cout << "Hash SHA-256: " << hashHex << std::endl;

    // Generar un par de claves RSA
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024);
    RSA::PublicKey publicKey(privateKey);

    // Cifrar el hash usando RSA
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    SecByteBlock encrypted(encryptor.CiphertextLength(sizeof(digest)));
    encryptor.Encrypt(rng, digest, sizeof(digest), encrypted);

    // Mostrar el resultado cifrado en hexadecimal
    std::string encryptedHex;
    StringSource(encrypted, encrypted.size(), true, new HexEncoder(new StringSink(encryptedHex)));
    std::cout << "Hash cifrado: " << encryptedHex << std::endl;

    return 0;
}
