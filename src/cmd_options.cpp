#include "cmd_options.h"
#include <iostream>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help", "produce help message")("command", po::value<std::string>(),
                                                        "command: 'encrypt' or 'decrypt' or 'checksum'")(
        "input,i", po::value<std::string>(), "input file")("output,o", po::value<std::string>(), "output file")(
        "password,p", po::value<std::string>(), "password");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    command_ = ProgramOptions::COMMAND_TYPE::UNKNOWN;
    inputFile_.clear();
    outputFile_.clear();
    password_.clear();

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc_ << std::endl;
        return;
    }

    if (vm.count("command")) {
        const auto cmd = vm["command"].as<std::string>();
        if (const auto it = commandMapping_.find(cmd); it != commandMapping_.cend()) {
            command_ = it->second;
        }
    }

    if (vm.count("input")) {
        inputFile_ = vm["input"].as<std::string>();
    }

    if (vm.count("output")) {
        outputFile_ = vm["output"].as<std::string>();
    }

    if (vm.count("password")) {
        password_ = vm["password"].as<std::string>();
    }
}

}  // namespace CryptoGuard
