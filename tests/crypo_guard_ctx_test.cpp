#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <vector>

using namespace CryptoGuard;

namespace {

const std::string passwordRef = "12341234";
const std::string textRef = "01234567890123456789";

//"؆W�I6/M���᪈�PM'tV̽���?~�";
const std::vector<uint8_t> textEncryptedRef = {0xd8, 0x86, 0x7f, 0x57, 0xc5, 0x49, 0x36, 0x2f, 0x4d, 0xab, 0xf2,
                                               0xea, 0xe1, 0xaa, 0x88, 0x0e, 0xcd, 0x50, 0x4d, 0x27, 0x74, 0x56,
                                               0xcc, 0xbd, 0x94, 0xa8, 0xa7, 0x3f, 0x7e, 0xb7, 0x1b, 0x30};

}  // namespace

TEST(CryptoGuardCtx, TestEncryptFromMain) {
    CryptoGuardCtx guard;

    std::stringstream in(std::ios::in | std::ios::out);
    std::stringstream out(std::ios::in | std::ios::out);

    in.write(textRef.data(), textRef.size());

    EXPECT_NO_THROW(guard.EncryptFile(in, out, passwordRef));
    EXPECT_NE(out.str(), textRef);

    const auto str = out.str();
    std::vector<uint8_t> encrypted(str.begin(), str.end());
    EXPECT_EQ(encrypted, textEncryptedRef);
}

TEST(CryptoGuardCtx, TestEncryptEmpty) {
    CryptoGuardCtx guard;

    const std::string password = "password";
    std::stringstream in(std::ios::in | std::ios::out);
    std::stringstream out(std::ios::in | std::ios::out);

    EXPECT_NO_THROW(guard.EncryptFile(in, out, password));
    EXPECT_EQ(out.str().size(), 16u);
}

TEST(EncryptFileTest, TestEncryptBadStreams) {
    CryptoGuardCtx guard;

    {
        const std::string password = "password1";
        std::stringstream in(std::ios::in | std::ios::out);
        in.setstate(std::ios::badbit);

        std::stringstream out(std::ios::in | std::ios::out);

        EXPECT_THROW(guard.EncryptFile(in, out, password), std::exception);
    }

    {
        const std::string password = "password2";
        std::stringstream in(std::ios::in | std::ios::out);

        std::stringstream out(std::ios::in | std::ios::out);
        out.setstate(std::ios::badbit);

        EXPECT_THROW(guard.EncryptFile(in, out, password), std::exception);
    }
}

TEST(CryptoGuardCtx, TestDecryptFromMain) {
    CryptoGuardCtx guard;

    std::stringstream in(std::ios::in | std::ios::out);
    std::stringstream out(std::ios::in | std::ios::out);

    in.write(reinterpret_cast<const char *>(textEncryptedRef.data()), textEncryptedRef.size());

    EXPECT_NO_THROW(guard.DecryptFile(in, out, passwordRef));
    EXPECT_EQ(out.str(), textRef);
}

TEST(CryptoGuardCtx, TestDecryptEmpty) {
    CryptoGuardCtx guard;

    const std::string password = "password";
    std::stringstream in(std::ios::in | std::ios::out);
    std::stringstream out(std::ios::in | std::ios::out);

    EXPECT_THROW(guard.DecryptFile(in, out, password), std::exception);
}

TEST(EncryptFileTest, TestDecryptBadStreams) {
    CryptoGuardCtx guard;

    {
        const std::string password = "password1";
        std::stringstream in(std::ios::in | std::ios::out);
        in.setstate(std::ios::badbit);

        std::stringstream out(std::ios::in | std::ios::out);

        EXPECT_THROW(guard.DecryptFile(in, out, password), std::exception);
    }

    {
        const std::string password = "password2";
        std::stringstream in(std::ios::in | std::ios::out);

        std::stringstream out(std::ios::in | std::ios::out);
        out.setstate(std::ios::badbit);

        EXPECT_THROW(guard.DecryptFile(in, out, password), std::exception);
    }
}

TEST(EncryptFileTest, TestCalculateChecksumBadStream) {
    CryptoGuardCtx guard;

    std::stringstream in(std::ios::in | std::ios::out);
    in.setstate(std::ios::badbit);
    EXPECT_THROW(guard.CalculateChecksum(in), std::exception);
}

TEST(EncryptFileTest, TestCalculateChecksumSimple) {
    CryptoGuardCtx guard;

    std::stringstream in(std::ios::in | std::ios::out);
    const std::string text = "Hello OpenSSL crypto world!\n";
    const std::string hashRef = "703def64f94beae6152170318053adf95524d7b1936be47f7dc073123e5c8974";
    in.write(text.data(), text.size());
    const auto hash = guard.CalculateChecksum(in);
    EXPECT_EQ(hash, hashRef);
}

TEST(EncryptFileTest, TestCalculateChecksumWithEncrypt) {
    CryptoGuardCtx guard;

    const std::string password = "12345";
    std::stringstream in1(std::ios::in | std::ios::out);
    const std::string text = "This is the test string";
    in1.write(text.data(), text.size());
    const auto hashBefore = guard.CalculateChecksum(in1);

    std::stringstream in2(std::ios::in | std::ios::out);
    std::stringstream out2(std::ios::in | std::ios::out);
    in2.write(text.data(), text.size());
    guard.EncryptFile(in2, out2, password);
    const auto encryptedStr = out2.str();

    std::stringstream in3(std::ios::in | std::ios::out);
    std::stringstream out3(std::ios::in | std::ios::out);
    in3.write(encryptedStr.data(), encryptedStr.size());
    guard.DecryptFile(in3, out3, password);
    const auto decryptedStr = out3.str();

    std::stringstream in4(std::ios::in | std::ios::out);
    in4.write(decryptedStr.data(), decryptedStr.size());
    const auto hashAfter = guard.CalculateChecksum(in4);

    EXPECT_EQ(hashBefore, hashAfter);
}
