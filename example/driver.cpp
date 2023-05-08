#include <chrono>
#include <fstream>
#include <iostream>

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "usage: driver <in> <out> <path>\n";
        return 1;
    }

    std::ifstream in{argv[1]};
    std::ofstream out{argv[2]};
    const char *const path = argv[3];
    std::string buffer;

    for (;;) {
        const auto before = std::chrono::steady_clock::now();
        out << path << std::endl;
        if (!std::getline(in, buffer)) {
            std::cerr << "Failed to read line from input file.\n";
            return 2;
        }
        const auto after = std::chrono::steady_clock::now();
        std::cout << std::chrono::duration_cast<std::chrono::nanoseconds>(after - before).count() << std::endl;
    }
}
