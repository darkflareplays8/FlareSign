#include "ZsignWrapper.h"
#include "zsign/zsign.h"
#include <string.h>

ZsignResult zsign_sign_ipa(
    const char* ipaPath,
    const char* outputPath,
    const char* p12Path,
    const char* p12Password,
    const char* provisionPath,
    const char* bundleID,
    const char* appName,
    const char* teamID
) {
    ZsignResult result;
    memset(&result, 0, sizeof(result));

    ZSign zsign;
    zsign.SetP12(p12Path, p12Password);
    zsign.SetProvision(provisionPath);
    if (bundleID && strlen(bundleID) > 0) zsign.SetBundleID(bundleID);
    if (appName && strlen(appName) > 0) zsign.SetDisplayName(appName);
    if (teamID && strlen(teamID) > 0) zsign.SetTeamID(teamID);

    bool success = zsign.SignIPA(ipaPath, outputPath);
    if (success) {
        result.success = 1;
        strncpy(result.outputPath, outputPath, sizeof(result.outputPath) - 1);
    } else {
        result.success = 0;
        strncpy(result.errorMessage, "zsign failed to sign IPA", sizeof(result.errorMessage) - 1);
    }
    return result;
}
