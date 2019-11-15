using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.COSE;
using Com.AugustCellars.WebToken.CWT;
using Com.AugustCellars.CoAP.OAuth;
using Com.AugustCellars.WebToken.Common;

namespace TestServer
{
    class AuthorizationEvaluate
    {

        public bool CheckAccess(Method operation, string url, OneKey keyIdentity)
        {
            return CheckAccess(operation, url, (List<Cwt>)keyIdentity.UserData);
        }

        public bool CheckAccess(Method operation, string url, SecurityContext context)
        {
            return CheckAccess(operation, url, (List<Cwt>)context.UserData);
        }

        public bool CheckAccess(Method operation, string url, List<Cwt> cwtList)
        {
            foreach (Cwt cwt in cwtList) {
                if (CheckAccess(operation, url, cwt)) return true;
            }
            return false;
        }

        public bool CheckAccess(Method operation, string audience, string scope, OneKey context)
        {
            return CheckAccess(operation, audience, scope, (List<Cwt>) context.UserData);
        }

        public bool CheckAccess(Method operation, string url, Cwt cwt)
        {
            Permission p = new Permission(url, operation);
            PermissionSet permissionSet = new PermissionSet(cwt.GetClaim(ClaimId.Scope));

            return permissionSet.Allows(p);
        }

        public bool CheckAccess(Method operation, string audience, string scope, SecurityContext context)
        {
            return false;
        }

        public bool CheckAccess(Method operation, string audience, string scope, List<Cwt> cwtList)
        {
            if (cwtList == null) return false;

            foreach (Cwt cwt in cwtList) {
                if (CheckAccess(operation, scope, cwt)) return true;
            }
            return false;
        }

        public bool CheckAccess(Method operation, string audience, string scope, Cwt cwt)
        {
            Permission p = new Permission(scope, operation);
            PermissionSet permissionSet = new PermissionSet(cwt.GetClaim(ClaimId.Scope));

            return permissionSet.Allows(p);
        }
    }
}
