/**
 * Licensed to Cloudera, Inc. under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Cloudera, Inc. licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cloudera.alfredo.client;

/**
 * Exception thrown when an authentication error occurrs.
 */
public class AuthenticationException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = -626133712701141278L;
    
    public AuthenticationExceptionCode errorCode;
    /**
     * Creates an <code>AuthenticationException</code>.
     *
     * @param cause original exception.
     */
    public AuthenticationException(Throwable cause, AuthenticationExceptionCode errorCode) {
        super(cause);
        this.errorCode = errorCode;
    }

    /**
     * Creates an <code>AuthenticationException</code>.
     *
     * @param msg exception message.
     */
    public AuthenticationException(String msg, AuthenticationExceptionCode errorCode) {
        super(msg);
        this.errorCode = errorCode;
    }

    /**
     * Creates an <code>AuthenticationException</code>.
     *
     * @param msg exception message.
     * @param cause original exception.
     */
    public AuthenticationException(String msg, Throwable cause, AuthenticationExceptionCode errorCode) {
        super(msg, cause);
        this.errorCode = errorCode;
    }
    
    public enum AuthenticationExceptionCode
    {
        TOKEN_EXPIRED                        (0, "AuthenticationToken expired"),
        INVALID_TYPE                         (1, "Invalid AuthenticationToken type"),
        INVALID_TOKEN                        (2, "Invalid authentication token"),
        ANONYMOUS_DISALLOWED                 (3, "Anonymous requests are disallowed"),
        TOKEN_SIGNER_EXCEPTION               (4, "Invalid signed token"),
        INVALID_SPNEGO_SEQUENCE              (5, "Invalid SPNEGO sequence"),
        AUTHENTICATION_FAILED_HTTP_RESP_CODE (6, "Authentication failed with http resp code"),
        LOGIN_EXCEPTION                      (7, "Login exception"),
        PRIVILEGED_ACTION_EXCEPTION          (8, "Privileged action exception"),
        INVALID_TOKEN_STRING                 (9, "Invalid token string, missing attributes");

        private final int code;
        private final String description;

        private AuthenticationExceptionCode(int code, String description)
        {
            this.code = code;
            this.description = description;
        }

        public String getDescription()
        {
            return description;
        }

        public int getCode()
        {
            return code;
        }

        @Override
        public String toString()
        {
           return code + ": " + description;
        }

    }
}
