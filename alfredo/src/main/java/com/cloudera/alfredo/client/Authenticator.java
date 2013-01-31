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


import java.io.IOException;
import java.net.URL;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;

/**
 * Interface for client authentication mechanisms.
 * <p/>
 * Implementations are use-once instances, they don't need to be thread safe.
 */
public interface Authenticator {

    /**
     * Authenticates against a URL and returns a {@link AuthenticatedURL.Token} to be
     * used by subsequent requests.
     *
     * @param url the URl to authenticate against.
     * @param token the authencation token being used for the user.
     * @throws IOException if an IO error occurred.
     * @throws AuthenticationException if an authentication error occurred.
     */
    public void authenticate(URL url, AuthenticatedURL.Token token) throws IOException, AuthenticationException;

    
    /**
     * Setter for optional SSLSocketFactory
     * @param socketFactory, if not set implementations should use system defaults
     */
    public void setSslSocketFactory(SSLSocketFactory socketFactory);

    /**
     * Setter for optional HostnameVerifier
     * @param hostVerifier, if not set implementations should use system defaults
     */
    public void setHostnameVerifier(HostnameVerifier hostVerifier);
    
}
