#ifndef ZsignWrapper_h
#define ZsignWrapper_h

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int success;
    char errorMessage[512];
    char outputPath[1024];
} ZsignResult;

ZsignResult zsign_sign_ipa(
    const char* ipaPath,
    const char* outputPath,
    const char* p12Path,
    const char* p12Password,
    const char* provisionPath,
    const char* bundleID,
    const char* appName,
    const char* teamID
);

#ifdef __cplusplus
}
#endif

#endif
