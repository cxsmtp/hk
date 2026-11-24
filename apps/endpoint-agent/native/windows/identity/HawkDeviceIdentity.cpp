#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>

#include <iostream>
#include <string>
#include <vector>

namespace {
constexpr DWORD HAWK_IDENTITY_MAX_INPUT_BYTES = 64U * 1024U;

struct ProviderHandle {
    NCRYPT_PROV_HANDLE value = 0;
    ~ProviderHandle() { if (value != 0) NCryptFreeObject(value); }
};

struct KeyHandle {
    NCRYPT_KEY_HANDLE value = 0;
    bool deleted = false;
    ~KeyHandle() { if (value != 0 && !deleted) NCryptFreeObject(value); }
};

bool SafeKeyName(const wchar_t* value) {
    if (value == nullptr) return false;
    const size_t length = wcslen(value);
    if (length == 0 || length > 160) return false;
    for (size_t index = 0; index < length; ++index) {
        const wchar_t character = value[index];
        if (!((character >= L'A' && character <= L'Z') ||
              (character >= L'a' && character <= L'z') ||
              (character >= L'0' && character <= L'9') ||
              character == L'.' || character == L'_' || character == L'-')) {
            return false;
        }
    }
    return true;
}

void Failure() {
    std::cout << "{\"ok\":false}" << std::endl;
}

std::string Base64(const std::vector<UCHAR>& bytes) {
    DWORD required = 0;
    if (!CryptBinaryToStringA(
            bytes.data(), static_cast<DWORD>(bytes.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &required)) {
        return {};
    }
    std::string encoded(required, '\0');
    if (!CryptBinaryToStringA(
            bytes.data(), static_cast<DWORD>(bytes.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encoded.data(), &required)) {
        return {};
    }
    if (!encoded.empty() && encoded.back() == '\0') encoded.pop_back();
    return encoded;
}

bool ReadBoundedStdin(std::vector<UCHAR>* bytes) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input == nullptr || input == INVALID_HANDLE_VALUE) return false;
    UCHAR buffer[4096];
    while (true) {
        DWORD observed = 0;
        if (!ReadFile(input, buffer, sizeof(buffer), &observed, nullptr)) {
            return GetLastError() == ERROR_BROKEN_PIPE;
        }
        if (observed == 0) return true;
        if (bytes->size() + observed > HAWK_IDENTITY_MAX_INPUT_BYTES) return false;
        bytes->insert(bytes->end(), buffer, buffer + observed);
    }
}

bool Sha256(const std::vector<UCHAR>& bytes, UCHAR digest[32]) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectBytes = 0;
    DWORD digestBytes = 0;
    DWORD copied = 0;
    std::vector<UCHAR> object;
    bool ok = false;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) goto Cleanup;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &copied, 0))) goto Cleanup;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(
            algorithm, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&digestBytes), sizeof(digestBytes), &copied, 0)) ||
        digestBytes != 32) goto Cleanup;
    object.resize(objectBytes);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(
            algorithm, &hash, object.data(), objectBytes, nullptr, 0, 0))) goto Cleanup;
    if (!bytes.empty() && !BCRYPT_SUCCESS(BCryptHashData(
            hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0))) goto Cleanup;
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, digestBytes, 0))) goto Cleanup;
    ok = true;
Cleanup:
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!object.empty()) SecureZeroMemory(object.data(), object.size());
    return ok;
}

bool HardwareProvider(NCRYPT_PROV_HANDLE provider) {
    DWORD implementation = 0;
    DWORD copied = 0;
    return NCryptGetProperty(
               provider, NCRYPT_IMPL_TYPE_PROPERTY,
               reinterpret_cast<PBYTE>(&implementation), sizeof(implementation),
               &copied, 0) == ERROR_SUCCESS &&
           (implementation & NCRYPT_IMPL_HARDWARE_FLAG) != 0;
}

SECURITY_STATUS OpenMachineKey(
    NCRYPT_PROV_HANDLE provider,
    const wchar_t* keyName,
    NCRYPT_KEY_HANDLE* key
) {
    return NCryptOpenKey(provider, key, keyName, 0, NCRYPT_MACHINE_KEY_FLAG);
}

bool ValidMachineKeyProperties(NCRYPT_KEY_HANDLE key) {
    wchar_t algorithmGroup[32] = {};
    DWORD lengthBits = 0;
    DWORD usage = 0;
    DWORD exportPolicy = 0;
    DWORD copied = 0;
    return NCryptGetProperty(
               key, NCRYPT_ALGORITHM_GROUP_PROPERTY,
               reinterpret_cast<PBYTE>(algorithmGroup), sizeof(algorithmGroup),
               &copied, 0) == ERROR_SUCCESS &&
           wcscmp(algorithmGroup, NCRYPT_ECDSA_ALGORITHM_GROUP) == 0 &&
           NCryptGetProperty(
               key, NCRYPT_LENGTH_PROPERTY,
               reinterpret_cast<PBYTE>(&lengthBits), sizeof(lengthBits),
               &copied, 0) == ERROR_SUCCESS && lengthBits == 256 &&
           NCryptGetProperty(
               key, NCRYPT_KEY_USAGE_PROPERTY,
               reinterpret_cast<PBYTE>(&usage), sizeof(usage),
               &copied, 0) == ERROR_SUCCESS && usage == NCRYPT_ALLOW_SIGNING_FLAG &&
           NCryptGetProperty(
               key, NCRYPT_EXPORT_POLICY_PROPERTY,
               reinterpret_cast<PBYTE>(&exportPolicy), sizeof(exportPolicy),
               &copied, 0) == ERROR_SUCCESS && exportPolicy == 0;
}

bool EnsureMachineKey(
    NCRYPT_PROV_HANDLE provider,
    const wchar_t* keyName,
    KeyHandle* key
) {
    SECURITY_STATUS status = OpenMachineKey(provider, keyName, &key->value);
    if (status == ERROR_SUCCESS) return ValidMachineKeyProperties(key->value);
    if (status != NTE_BAD_KEYSET && status != NTE_NOT_FOUND) return false;
    status = NCryptCreatePersistedKey(
        provider, &key->value, NCRYPT_ECDSA_P256_ALGORITHM, keyName, 0,
        NCRYPT_MACHINE_KEY_FLAG
    );
    if (status != ERROR_SUCCESS) return false;
    DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
    DWORD exportPolicy = 0;
    if (NCryptSetProperty(
            key->value, NCRYPT_KEY_USAGE_PROPERTY,
            reinterpret_cast<PBYTE>(&usage), sizeof(usage), 0) != ERROR_SUCCESS ||
        NCryptSetProperty(
            key->value, NCRYPT_EXPORT_POLICY_PROPERTY,
            reinterpret_cast<PBYTE>(&exportPolicy), sizeof(exportPolicy), 0) != ERROR_SUCCESS ||
        NCryptFinalizeKey(key->value, 0) != ERROR_SUCCESS) {
        return false;
    }
    return true;
}

bool PublicBlob(NCRYPT_KEY_HANDLE key, std::vector<UCHAR>* output) {
    DWORD required = 0;
    if (NCryptExportKey(
            key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0,
            &required, 0) != ERROR_SUCCESS || required != 72) return false;
    output->resize(required);
    return NCryptExportKey(
               key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, output->data(), required,
               &required, 0) == ERROR_SUCCESS;
}

void StatusJson(bool exists) {
    std::cout
        << "{\"ok\":true,\"available\":true,\"hardware_backed\":true,"
        << "\"tpm_present\":true,\"tpm_ready\":true,"
        << "\"provider\":\"Microsoft Platform Crypto Provider\","
        << "\"exists\":" << (exists ? "true" : "false") << "}"
        << std::endl;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 3 || !SafeKeyName(argv[2])) { Failure(); return 2; }
    const std::wstring operation(argv[1]);
    if (operation != L"status" && operation != L"ensure" &&
        operation != L"sign" && operation != L"destroy") {
        Failure(); return 2;
    }
    ProviderHandle provider;
    if (NCryptOpenStorageProvider(
            &provider.value, MS_PLATFORM_CRYPTO_PROVIDER, 0) != ERROR_SUCCESS ||
        !HardwareProvider(provider.value)) {
        Failure(); return 3;
    }
    KeyHandle key;
    SECURITY_STATUS openStatus = OpenMachineKey(provider.value, argv[2], &key.value);
    if (openStatus != ERROR_SUCCESS &&
        openStatus != NTE_BAD_KEYSET && openStatus != NTE_NOT_FOUND) {
        Failure(); return 10;
    }
    if (openStatus == ERROR_SUCCESS && !ValidMachineKeyProperties(key.value)) {
        Failure(); return 9;
    }
    const bool exists = openStatus == ERROR_SUCCESS;
    if (operation == L"status") { StatusJson(exists); return 0; }
    if (operation == L"ensure") {
        if (!exists && !EnsureMachineKey(provider.value, argv[2], &key)) {
            Failure(); return 4;
        }
        std::vector<UCHAR> publicBlob;
        if (!PublicBlob(key.value, &publicBlob)) { Failure(); return 4; }
        const std::string encoded = Base64(publicBlob);
        if (encoded.empty()) { Failure(); return 4; }
        std::cout
            << "{\"ok\":true,\"available\":true,\"hardware_backed\":true,"
            << "\"tpm_present\":true,\"tpm_ready\":true,"
            << "\"provider\":\"Microsoft Platform Crypto Provider\","
            << "\"public_key_blob\":\"" << encoded << "\"}"
            << std::endl;
        return 0;
    }
    if (!exists) { Failure(); return 5; }
    if (operation == L"destroy") {
        if (NCryptDeleteKey(key.value, 0) != ERROR_SUCCESS) { Failure(); return 6; }
        key.deleted = true;
        key.value = 0;
        StatusJson(false);
        return 0;
    }
    std::vector<UCHAR> input;
    UCHAR digest[32];
    if (!ReadBoundedStdin(&input) || !Sha256(input, digest)) {
        if (!input.empty()) SecureZeroMemory(input.data(), input.size());
        Failure(); return 7;
    }
    DWORD signatureBytes = 0;
    SECURITY_STATUS status = NCryptSignHash(
        key.value, nullptr, digest, sizeof(digest), nullptr, 0,
        &signatureBytes, 0
    );
    std::vector<UCHAR> signature(signatureBytes);
    if (status != ERROR_SUCCESS || signatureBytes != 64 ||
        NCryptSignHash(
            key.value, nullptr, digest, sizeof(digest), signature.data(),
            signatureBytes, &signatureBytes, 0) != ERROR_SUCCESS ||
        signatureBytes != 64) {
        SecureZeroMemory(digest, sizeof(digest));
        if (!input.empty()) SecureZeroMemory(input.data(), input.size());
        Failure(); return 8;
    }
    SecureZeroMemory(digest, sizeof(digest));
    if (!input.empty()) SecureZeroMemory(input.data(), input.size());
    const std::string encoded = Base64(signature);
    if (encoded.empty()) { Failure(); return 8; }
    std::cout
        << "{\"ok\":true,\"available\":true,\"hardware_backed\":true,"
        << "\"tpm_present\":true,\"tpm_ready\":true,"
        << "\"provider\":\"Microsoft Platform Crypto Provider\","
        << "\"signature\":\"" << encoded << "\"}"
        << std::endl;
    SecureZeroMemory(signature.data(), signature.size());
    return 0;
}
