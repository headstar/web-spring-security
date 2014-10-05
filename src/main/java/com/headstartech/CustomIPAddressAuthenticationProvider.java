package com.headstartech;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * Created by per on 10/5/14.
 */
public class CustomIPAddressAuthenticationProvider implements AuthenticationProvider
{

    Logger logger = LoggerFactory.getLogger(CustomIPAddressAuthenticationProvider.class);
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();


    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {


        WebAuthenticationDetails wad = null;
        String userIPAddress         = null;
        boolean isAuthenticatedByIP  = false;

        // Get the IP address of the user tyring to use the site
        wad = (WebAuthenticationDetails) authentication.getDetails();
        userIPAddress = wad.getRemoteAddress();

        logger.info("userIPAddress == " + userIPAddress);

        // Compare the user's IP Address with the IP address in the database
        // stored in the USERS_AUTHENTICATED_BY_IP table & joined to the
        // USERS tabe to make sure the IP Address has a current user
        //isAuthenticatedByIP =  someDataObject.hasIPAddress(userIPAddress);
        isAuthenticatedByIP = true;

        // Authenticated, the user's IP address matches one in the database
        if (isAuthenticatedByIP) {
            logger.info("isAuthenticatedByIP is true, IP Addresses match");
            UserDetails user = null;
            UsernamePasswordAuthenticationToken result = null;
            result = new UsernamePasswordAuthenticationToken("user", "user");
            result.setDetails(authentication.getDetails());

            return result;
        }

        // Authentication didn't happen, return null to signal that the
        // AuthenticationManager should move on to the next Authentication provider
        return null;
    }


    @Override
    public boolean supports(Class<? extends Object> authentication)
    {
        // copied it from AbstractUserDetailsAuthenticationProvider
        return(UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
