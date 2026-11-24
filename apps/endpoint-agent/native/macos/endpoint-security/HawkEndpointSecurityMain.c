#include <dispatch/dispatch.h>

int HawkStartEndpointSecurityClient(void);
int HawkStartEndpointPolicyXPCService(void);

int main(void) {
    const int policyService = HawkStartEndpointPolicyXPCService();
    if (policyService != 0) {
        return policyService;
    }
    const int result = HawkStartEndpointSecurityClient();
    if (result != 0) {
        return result;
    }
    dispatch_main();
}
