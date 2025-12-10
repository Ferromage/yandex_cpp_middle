#include "crypto_guard_ctx.h"

#include <iomanip>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }

    ~Impl() { EVP_cleanup(); }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream) {
            throw std::runtime_error("EncryptFile: fail state of input stream");
        }
        if (!outStream) {
            throw std::runtime_error("EncryptFile: fail state of output stream (1)");
        }

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;

        auto ctxDeleter = [](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); };
        std::unique_ptr<EVP_CIPHER_CTX, decltype(ctxDeleter)> ctx{EVP_CIPHER_CTX_new()};

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error("EncryptFile: error on EVP_CipherInit_ex()");
        }

        std::vector<unsigned char> inBuf(1024);
        std::vector<unsigned char> outBuf(inBuf.size());
        int outLen;
        while (inStream && outStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            const int inLen = static_cast<int>(inStream.gcount());
            if (inLen == 0) {
                break;
            }

            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen)) {
                throw std::runtime_error("EncryptFile: error on EVP_CipherUpdate()");
            }

            outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        }

        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error("EncryptFile: error on EVP_CipherFinal_ex()");
        }
        if (!outStream) {
            throw std::runtime_error("EncryptFile: fail state of output stream (2)");
        }
        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream) {
            throw std::runtime_error("DecryptFile: fail state of input stream");
        }
        if (!outStream) {
            throw std::runtime_error("DecryptFile: fail state of output stream (1)");
        }

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;

        auto ctxDeleter = [](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); };
        std::unique_ptr<EVP_CIPHER_CTX, decltype(ctxDeleter)> ctx{EVP_CIPHER_CTX_new()};

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error("DecryptFile: error on EVP_CipherInit_ex()");
        }

        std::vector<unsigned char> inBuf(1024);
        std::vector<unsigned char> outBuf(inBuf.size());
        int outLen;
        while (inStream && outStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            const int inLen = static_cast<int>(inStream.gcount());
            if (inLen == 0) {
                break;
            }

            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen)) {
                throw std::runtime_error("DecryptFile: error on EVP_CipherUpdate()");
            }

            outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        }

        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error("DecryptFile: error on EVP_CipherFinal_ex()");
        }
        if (!outStream) {
            throw std::runtime_error("DecryptFile: fail state of output stream (2)");
        }
        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        if (!inStream) {
            throw std::runtime_error("CalculateChecksum: fail state of input stream");
        }

        auto ctxDeleter = [](EVP_MD_CTX *ptr) { EVP_MD_CTX_free(ptr); };
        std::unique_ptr<EVP_MD_CTX, decltype(ctxDeleter)> ctx(EVP_MD_CTX_new());
        if (!ctx) {
            throw std::runtime_error("CalculateChecksum: message digest create failed");
        }

        if (!EVP_DigestInit_ex(ctx.get(), EVP_sha256(), NULL)) {
            throw std::runtime_error("CalculateChecksum: error on EVP_DigestInit_ex()");
        }

        std::vector<std::byte> inBuf(1024);
        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            const auto inLen = static_cast<int>(inStream.gcount());
            if (inLen == 0) {
                break;
            }

            if (!EVP_DigestUpdate(ctx.get(), inBuf.data(), inLen)) {
                throw std::runtime_error("CalculateChecksum: error on EVP_DigestUpdate()");
            }
        }

        uint8_t hash[EVP_MAX_MD_SIZE];
        unsigned int lengthOfHash = 0;
        if (!EVP_DigestFinal_ex(ctx.get(), hash, &lengthOfHash)) {
            throw std::runtime_error("CalculateChecksum: error on EVP_DigestFinal_ex()");
        }

        std::ostringstream out;
        for (auto i = 0; i < lengthOfHash; ++i) {
            out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return out.str();
    }

private:
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_{std::make_unique<Impl>()} {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    if (pImpl_) {
        pImpl_->EncryptFile(inStream, outStream, password);
    }
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    if (pImpl_) {
        pImpl_->DecryptFile(inStream, outStream, password);
    }
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    if (pImpl_) {
        return pImpl_->CalculateChecksum(inStream);
    }
    return {};
}

}  // namespace CryptoGuard
