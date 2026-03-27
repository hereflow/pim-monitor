#include "pch.hpp"
#include "SignatureVerifier.hpp"

#include <Softpub.h>
#include <WinTrust.h>
#include <wincrypt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

std::string SignatureVerifier::GetProcessPath(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};

    char path[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    QueryFullProcessImageNameA(h, 0, path, &sz);
    CloseHandle(h);
    return path;
}

std::string SignatureVerifier::ExtractSignerName(const std::string& filePath) {
    std::wstring wide(filePath.begin(), filePath.end());

    HCERTSTORE         hStore   = nullptr;
    HCRYPTMSG          hMsg     = nullptr;
    PCCERT_CONTEXT     pCert    = nullptr;
    std::string        signer;

    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        wide.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, &dwEncoding, &dwContentType, &dwFormatType,
        &hStore, &hMsg, nullptr);

    if (!ok) return {};

    DWORD signerInfoSize = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize);

    if (signerInfoSize > 0) {
        std::vector<uint8_t> buf(signerInfoSize);
        auto pSignerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());

        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &signerInfoSize)) {
            CERT_INFO ci{};
            ci.Issuer       = pSignerInfo->Issuer;
            ci.SerialNumber = pSignerInfo->SerialNumber;

            pCert = CertFindCertificateInStore(
                hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0, CERT_FIND_SUBJECT_CERT, &ci, nullptr);

            if (pCert) {
                char name[512]{};
                DWORD nameLen = CertGetNameStringA(
                    pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, sizeof(name));
                if (nameLen > 1) signer = name;
                CertFreeCertificateContext(pCert);
            }
        }
    }

    if (hMsg)   CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);

    return signer;
}

SignatureInfo SignatureVerifier::Verify(const std::string& filePath) {
    SignatureInfo info{};
    info.status    = SignatureStatus::Error;
    info.isTrusted = false;

    if (filePath.empty()) return info;

    std::wstring wide(filePath.begin(), filePath.end());

    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct      = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = wide.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct            = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice          = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice       = WTD_CHOICE_FILE;
    trustData.pFile               = &fileInfo;
    trustData.dwStateAction       = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags         = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG result = WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE), &actionId, &trustData);

    switch (result) {
        case ERROR_SUCCESS:
            info.status    = SignatureStatus::Valid;
            info.isTrusted = true;
            break;
        case TRUST_E_NOSIGNATURE:
            info.status = SignatureStatus::Unsigned;
            break;
        case TRUST_E_EXPLICIT_DISTRUST:
        case TRUST_E_SUBJECT_NOT_TRUSTED:
            info.status = SignatureStatus::Untrusted;
            break;
        case CERT_E_EXPIRED:
            info.status = SignatureStatus::Expired;
            break;
        default:
            info.status = SignatureStatus::Invalid;
            break;
    }

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionId, &trustData);

    info.signer = ExtractSignerName(filePath);

    return info;
}

SignatureInfo SignatureVerifier::VerifyPid(uint32_t pid) {
    std::string path = GetProcessPath(pid);
    if (path.empty()) {
        SignatureInfo info{};
        info.status    = SignatureStatus::Error;
        info.isTrusted = false;
        return info;
    }
    return Verify(path);
}
