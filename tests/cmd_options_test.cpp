#include "cmd_options.h"
#include <gtest/gtest.h>

using namespace CryptoGuard;

TEST(ProgramOptions, TestInitial) {
    ProgramOptions options;

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::UNKNOWN);
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());

    char arg0[] = "program_name";
    char *argv[] = {arg0};
    options.Parse(1, argv);

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::UNKNOWN);
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, TestParseCommand) {
    ProgramOptions options;
    char arg0[] = "program_name";
    char arg1[] = "--command";
    {
        char arg2[] = "encrypt";
        char *argv[] = {arg0, arg1, arg2};
        options.Parse(3, argv);
        EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    }
    {
        char arg2[] = "decrypt";
        char *argv[] = {arg0, arg1, arg2};
        options.Parse(3, argv);
        EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    }
    {
        char arg2[] = "checksum";
        char *argv[] = {arg0, arg1, arg2};
        options.Parse(3, argv);
        EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    }
    {
        char arg2[] = "unsupported_command";
        char *argv[] = {arg0, arg1, arg2};
        options.Parse(3, argv);
        EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::UNKNOWN);
    }
    {
        char *argv[] = {arg0, arg1};
        bool isOk = false;
        try {
            options.Parse(2, argv);
        } catch (std::exception &ex) {
            isOk = true;
        }
        EXPECT_TRUE(isOk);
    }
}

TEST(ProgramOptions, TestParseInputFile) {
    ProgramOptions options;
    char arg0[] = "program_name";
    {
        char arg1[] = "--input";
        char arg2[] = "file1";
        char *argv[] = {arg0, arg1, arg2};
        options.Parse(3, argv);
        EXPECT_EQ(options.GetInputFile(), "file1");
    }
    {
        char arg1[] = "-i";
        char arg2[] = "file2";
        char *argv[] = {arg0, arg1, arg2};
        options.Parse(3, argv);
        EXPECT_EQ(options.GetInputFile(), "file2");
    }
    {
        char arg1[] = "--input";
        char *argv[] = {arg0, arg1};
        bool isOk = false;
        try {
            options.Parse(2, argv);
        } catch (std::exception &ex) {
            isOk = true;
        }
        EXPECT_TRUE(isOk);
    }
    {
        char arg1[] = "-i";
        char *argv[] = {arg0, arg1};
        bool isOk = false;
        try {
            options.Parse(2, argv);
        } catch (std::exception &ex) {
            isOk = true;
        }
        EXPECT_TRUE(isOk);
    }
}

TEST(ProgramOptions, TestParseOutputFile) {
    ProgramOptions options;
    char arg0[] = "program_name";
    {
        char arg1[] = "--output";
        char arg2[] = "file1";
        char *argv[] = {arg0, arg1, arg2};
        options.Parse(3, argv);
        EXPECT_EQ(options.GetOutputFile(), "file1");
    }
    {
        char arg1[] = "-o";
        char arg2[] = "file2";
        char *argv[] = {arg0, arg1, arg2};
        options.Parse(3, argv);
        EXPECT_EQ(options.GetOutputFile(), "file2");
    }
    {
        char arg1[] = "--output";
        char *argv[] = {arg0, arg1};
        bool isOk = false;
        try {
            options.Parse(2, argv);
        } catch (std::exception &ex) {
            isOk = true;
        }
        EXPECT_TRUE(isOk);
    }
    {
        char arg1[] = "-o";
        char *argv[] = {arg0, arg1};
        bool isOk = false;
        try {
            options.Parse(2, argv);
        } catch (std::exception &ex) {
            isOk = true;
        }
        EXPECT_TRUE(isOk);
    }
}

TEST(ProgramOptions, TestParsePassword) {
    ProgramOptions options;
    char arg0[] = "program_name";
    {
        char arg1[] = "--password";
        char arg2[] = "pass123";
        char *argv[] = {arg0, arg1, arg2};
        options.Parse(3, argv);
        EXPECT_EQ(options.GetPassword(), "pass123");
    }
    {
        char arg1[] = "-p";
        char arg2[] = "new_pass";
        char *argv[] = {arg0, arg1, arg2};
        options.Parse(3, argv);
        EXPECT_EQ(options.GetPassword(), "new_pass");
    }
    {
        char arg1[] = "--password";
        char *argv[] = {arg0, arg1};
        bool isOk = false;
        try {
            options.Parse(2, argv);
        } catch (std::exception &ex) {
            isOk = true;
        }
        EXPECT_TRUE(isOk);
    }
    {
        char arg1[] = "-p";
        char *argv[] = {arg0, arg1};
        bool isOk = false;
        try {
            options.Parse(2, argv);
        } catch (std::exception &ex) {
            isOk = true;
        }
        EXPECT_TRUE(isOk);
    }
}

TEST(ProgramOptions, TestParseMiscellaneous) {
    ProgramOptions options;
    char arg0[] = "program_name";

    {
        char arg1[] = "-i";
        char arg2[] = "input.txt";
        char arg3[] = "-o";
        char arg4[] = "encrypted.txt";
        char arg5[] = "-p";
        char arg6[] = "1234";
        char arg7[] = "--command";
        char arg8[] = "encrypt";
        char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
        options.Parse(9, argv);

        EXPECT_EQ(options.GetInputFile(), "input.txt");
        EXPECT_EQ(options.GetOutputFile(), "encrypted.txt");
        EXPECT_EQ(options.GetPassword(), "1234");
        EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    }

    {
        char arg1[] = "-i";
        char arg2[] = "encrypted.txt";
        char arg3[] = "-o";
        char arg4[] = "decrypted.txt";
        char arg5[] = "-p";
        char arg6[] = "1234";
        char arg7[] = "--command";
        char arg8[] = "decrypt";
        char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
        options.Parse(9, argv);

        EXPECT_EQ(options.GetInputFile(), "encrypted.txt");
        EXPECT_EQ(options.GetOutputFile(), "decrypted.txt");
        EXPECT_EQ(options.GetPassword(), "1234");
        EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    }

    {
        char arg1[] = "-i";
        char arg2[] = "input.txt";
        char arg3[] = "--command";
        char arg4[] = "checksum";
        char *argv[] = {arg0, arg1, arg2, arg3, arg4};
        options.Parse(5, argv);

        EXPECT_EQ(options.GetInputFile(), "input.txt");
        EXPECT_TRUE(options.GetOutputFile().empty());
        EXPECT_TRUE(options.GetPassword().empty());
        EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    }
}