package org.wso2.sample.AuthenticationHandler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.DefaultAuthenticationRequestHandler;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;

public class CustomAuthenticationRequestHandler extends DefaultAuthenticationRequestHandler {

    private static final Log log = LogFactory.getLog(CustomAuthenticationRequestHandler.class);

    @Override
    protected void concludeFlow(HttpServletRequest request, HttpServletResponse response,
                                AuthenticationContext context) throws FrameworkException {

        log.info("Custom Authenticator1 is started");
        String userName = "";
        if (StringUtils.isNotBlank(context.getSequenceConfig().getAuthenticatedUser().getUserName())) {
            userName = context.getSequenceConfig().getAuthenticatedUser().getUserName();
            log.info("Authenticated User: " + userName);
        }

        if (StringUtils.equalsIgnoreCase(userName, "john")) {
            try {
                request.setAttribute("authenticatorFlowStatus", AuthenticatorFlowStatus.INCOMPLETE);
                response.sendRedirect(IdentityUtil.getServerURL(constructRedirectUrl("status=AuthenticationFailed&statusMsg=Blocked"), false, false));
            } catch (IOException ie) {
                log.error("Error occur while redirecting to the retry page:" + ie.getMessage() + "\n" + ie);
            }
        } else {
            super.concludeFlow(request, response, context);
        }
    }

    protected String constructRedirectUrl (String queryParms) {
        String redirectUrl = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
        if (StringUtils.isNotBlank(queryParms)) {
            //TODO: We need to validate if the query parameters are correct here. Also need to check if there is already parameters in the redirect Url
            redirectUrl = redirectUrl + "?" + queryParms;
        }
        return redirectUrl;
    }
}
