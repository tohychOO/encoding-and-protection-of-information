#include <gtest/gtest.h>
#include <fstream>
#include <random>
#include <thread>

#include "task.cpp"

TEST(PaddingTest_Work4, PKCS7_Basic) {
    PKCS7Padding padding;
    vector<uint8_t> data = {'H','e','l','l','o'};
    size_t blockSize = 8;
    
    auto padded = padding.addPadding(data, blockSize);
    EXPECT_EQ(padded.size(), 8);
    EXPECT_EQ(padded[5], 3);
    EXPECT_EQ(padded[6], 3);
    EXPECT_EQ(padded[7], 3);
    
    auto unpadded = padding.removePadding(padded, blockSize);
    EXPECT_EQ(unpadded, data);
}

TEST(PaddingTest_Work4, PKCS7_ExactBlock) {
    PKCS7Padding padding;
    vector<uint8_t> data = {1,2,3,4,5,6,7,8};
    size_t blockSize = 8;
    
    auto padded = padding.addPadding(data, blockSize);
    EXPECT_EQ(padded.size(), 16);
    for (size_t i = 8; i < 16; i++) {
        EXPECT_EQ(padded[i], 8);
    }
    
    auto unpadded = padding.removePadding(padded, blockSize);
    EXPECT_EQ(unpadded, data);
}

TEST(PaddingTest_Work4, ISO10126_Basic) {
    ISO10126Padding padding;
    vector<uint8_t> data = {'H','e','l','l','o'};
    size_t blockSize = 8;
    
    srand(42);
    
    auto padded = padding.addPadding(data, blockSize);
    EXPECT_EQ(padded.size(), 8);
    EXPECT_EQ(padded[7], 3);
    
    auto unpadded = padding.removePadding(padded, blockSize);
    EXPECT_EQ(unpadded, data);
}

class ModeTest_Work4 : public ::testing::Test {
protected:
    void SetUp() override {
        algo = make_unique<XORAlgorithm>(8, 8);
        key = {1,2,3,4,5,6,7,8};
        iv = {1,2,3,4,5,6,7,8};
        plainData = {'1','2','3','4','5','6','7','8'};
        multiBlockData = {'1','2','3','4','5','6','7','8','9','0','A','B','C','D','E','F'};
    }
    
    unique_ptr<XORAlgorithm> algo;
    vector<uint8_t> key;
    vector<uint8_t> iv;
    vector<uint8_t> plainData;
    vector<uint8_t> multiBlockData;
};

TEST_F(ModeTest_Work4, CFB_Basic) {
    CFBMode mode(iv);
    vector<uint8_t> encrypted, decrypted;
    
    mode.encrypt(plainData, encrypted, algo.get(), key);
    mode.decrypt(encrypted, decrypted, algo.get(), key);
    
    EXPECT_EQ(decrypted, plainData);
}

TEST_F(ModeTest_Work4, OFB_Basic) {
    OFBMode mode(iv);
    vector<uint8_t> encrypted, decrypted;
    
    mode.encrypt(plainData, encrypted, algo.get(), key);
    mode.decrypt(encrypted, decrypted, algo.get(), key);
    
    EXPECT_EQ(decrypted, plainData);
}

TEST_F(ModeTest_Work4, CTR_Basic) {
    CTRMode mode(iv);
    vector<uint8_t> encrypted, decrypted;
    
    mode.encrypt(plainData, encrypted, algo.get(), key);
    mode.decrypt(encrypted, decrypted, algo.get(), key);
    
    EXPECT_EQ(decrypted, plainData);
}

TEST_F(ModeTest_Work4, CTR_MultiThread) {
    CTRMode mode(iv);
    
    vector<uint8_t> encrypted1, encrypted2;
    vector<uint8_t> decrypted;
    
    mode.encrypt(multiBlockData, encrypted1, algo.get(), key, 1);
    mode.encrypt(multiBlockData, encrypted2, algo.get(), key, 4);
    
    EXPECT_EQ(encrypted1, encrypted2);
    
    mode.decrypt(encrypted1, decrypted, algo.get(), key, 4);
    EXPECT_EQ(decrypted, multiBlockData);
}

TEST_F(ModeTest_Work4, RandomDelta_Basic) {
    vector<vector<uint8_t>> params = {{1,0,0,0,0,0,0,0}};
    RandomDeltaMode mode(iv, params);
    
    vector<uint8_t> encrypted, decrypted;
    
    mode.encrypt(multiBlockData, encrypted, algo.get(), key);
    mode.decrypt(encrypted, decrypted, algo.get(), key);
    
    EXPECT_EQ(decrypted, multiBlockData);
}

TEST_F(ModeTest_Work4, RandomDelta_MultiThread) {
    vector<vector<uint8_t>> params = {{1,0,0,0,0,0,0,0}};
    RandomDeltaMode mode(iv, params);
    
    vector<uint8_t> encrypted1, encrypted2;
    vector<uint8_t> decrypted;
    
    mode.encrypt(multiBlockData, encrypted1, algo.get(), key, 1);
    mode.encrypt(multiBlockData, encrypted2, algo.get(), key, 4);
    
    EXPECT_EQ(encrypted1, encrypted2);
    
    mode.decrypt(encrypted1, decrypted, algo.get(), key, 4);
    EXPECT_EQ(decrypted, multiBlockData);
}

class ContextTest_Work4 : public ::testing::Test {
protected:
    void SetUp() override {
        key = {1,2,3,4,5,6,7,8};
        iv = {1,2,3,4,5,6,7,8};
        data = {'H','e','l','l','o',' ','W','o','r','l','d','!'};
    }
    
    vector<uint8_t> key;
    vector<uint8_t> iv;
    vector<uint8_t> data;
};

TEST_F(ContextTest_Work4, CFB_PKCS7) {
    auto algo = make_unique<XORAlgorithm>(8, 8);
    CipherContext cipher(
        std::move(algo),
        ModeType::CFB,
        PaddingType::PKCS7,
        iv
    );
    
    vector<uint8_t> encrypted, decrypted;
    
    cipher.encrypt(data, encrypted, key);
    cipher.decrypt(encrypted, decrypted, key);
    
    EXPECT_EQ(decrypted, data);
}

TEST_F(ContextTest_Work4, OFB_ISO10126) {
    auto algo = make_unique<XORAlgorithm>(8, 8);
    CipherContext cipher(
        std::move(algo),
        ModeType::OFB,
        PaddingType::ISO10126,
        iv
    );
    
    vector<uint8_t> encrypted, decrypted;
    
    cipher.encrypt(data, encrypted, key);
    cipher.decrypt(encrypted, decrypted, key);
    
    EXPECT_EQ(decrypted, data);
}

TEST_F(ContextTest_Work4, CTR_PKCS7) {
    auto algo = make_unique<XORAlgorithm>(8, 8);
    CipherContext cipher(
        std::move(algo),
        ModeType::CTR,
        PaddingType::PKCS7,
        iv
    );
    
    vector<uint8_t> encrypted, decrypted;
    
    cipher.encrypt(data, encrypted, key);
    cipher.decrypt(encrypted, decrypted, key);
    
    EXPECT_EQ(decrypted, data);
}

TEST_F(ContextTest_Work4, RandomDelta_PKCS7) {
    auto algo = make_unique<XORAlgorithm>(8, 8);
    vector<vector<uint8_t>> params = {{1,0,0,0,0,0,0,0}};
    
    CipherContext cipher(
        std::move(algo),
        ModeType::RandomDelta,
        PaddingType::PKCS7,
        iv,
        params
    );
    
    vector<uint8_t> encrypted, decrypted;
    
    cipher.encrypt(data, encrypted, key);
    cipher.decrypt(encrypted, decrypted, key);
    
    EXPECT_EQ(decrypted, data);
}

TEST(ExceptionTest_Work4, InvalidKeySize) {
    auto algo = make_unique<XORAlgorithm>(8, 8);
    CipherContext cipher(
        std::move(algo),
        ModeType::CTR,
        PaddingType::PKCS7,
        iv
    );
    
    vector<uint8_t> invalidKey = {1,2,3};
    vector<uint8_t> encrypted;
    
    EXPECT_THROW(cipher.encrypt(data, encrypted, invalidKey), InvalidKeyException);
}

TEST(ExceptionTest_Work4, NoIVForCBC) {
    EXPECT_THROW(CBCMode mode(vector<uint8_t>()), InvalidDataException);
}

TEST(ExceptionTest_Work4, NoIVForCFB) {
    EXPECT_THROW(CFBMode mode(vector<uint8_t>()), InvalidDataException);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}