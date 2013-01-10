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
package com.cloudera.alfredo.examples;

import com.cloudera.alfredo.client.AuthenticatedURL;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

/**
 * Example that uses <code>AuthenticatedURL</code>.
 */
public class HttpWhoClient {

    public static void main(String[] args) {
        try {
            if (args.length != 1) {
                System.err.println("Usage: <URL>");
                System.exit(-1);
            }
            
            HttpClient client = new DefaultHttpClient();
            HttpRequestBase method = new HttpGet(args[0]);
            
            AuthenticatedURL.Token token = new AuthenticatedURL.Token();
            URL url = method.getURI().toURL();
            token = new AuthenticatedURL().authenticateWithToken(url, token);
            // or you can specify a keytab + principal rather than use whats in the ticket cache
            //token = new AuthenticatedURL("/path/to/test.keytab", "HTTP/localhost").authenticateWithToken(url, token);
            method.addHeader("Cookie", AuthenticatedURL.AUTH_COOKIE + "=" + token);
            System.out.println();
            System.out.println("Token value: " + token);
            
            HttpResponse response = client.execute(method);
            
            System.out.println("Status code: " + response.getStatusLine().getStatusCode() + " " + response.getStatusLine().getReasonPhrase());
            System.out.println();
            if (response.getStatusLine().getStatusCode() == HttpURLConnection.HTTP_OK) {
            	System.out.println(EntityUtils.toString(response.getEntity()));
            }
            System.out.println();
        }
        catch (Exception ex) {
            System.err.println("ERROR: " + ex.getMessage());
            System.exit(-1);
        }
    }
}
