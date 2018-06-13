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

import com.google.common.collect.Lists;
import junit.framework.TestCase;
import org.mockito.Mockito;

import java.net.HttpURLConnection;
import java.util.*;

/**
 *
 */
public class TestAuthenticatedURL extends TestCase {

    public void testToken() throws Exception {
        AuthenticatedURL.Token token = new AuthenticatedURL.Token();
        assertFalse(token.isSet());
        token = new AuthenticatedURL.Token("foo");
        assertTrue(token.isSet());
        assertEquals("foo", token.toString());

        AuthenticatedURL.Token token1 = new AuthenticatedURL.Token();
        AuthenticatedURL.Token token2 = new AuthenticatedURL.Token();
        assertEquals(token1.hashCode(), token2.hashCode());
        assertTrue(token1.equals(token2));

        token1 = new AuthenticatedURL.Token();
        token2 = new AuthenticatedURL.Token("foo");
        assertNotSame(token1.hashCode(), token2.hashCode());
        assertFalse(token1.equals(token2));

        token1 = new AuthenticatedURL.Token("foo");
        token2 = new AuthenticatedURL.Token();
        assertNotSame(token1.hashCode(), token2.hashCode());
        assertFalse(token1.equals(token2));

        token1 = new AuthenticatedURL.Token("foo");
        token2 = new AuthenticatedURL.Token("foo");
        assertEquals(token1.hashCode(), token2.hashCode());
        assertTrue(token1.equals(token2));

        token1 = new AuthenticatedURL.Token("bar");
        token2 = new AuthenticatedURL.Token("foo");
        assertNotSame(token1.hashCode(), token2.hashCode());
        assertFalse(token1.equals(token2));

        token1 = new AuthenticatedURL.Token("foo");
        token2 = new AuthenticatedURL.Token("bar");
        assertNotSame(token1.hashCode(), token2.hashCode());
        assertFalse(token1.equals(token2));
    }

    public void testInjectToken() throws Exception {
        HttpURLConnection conn = Mockito.mock(HttpURLConnection.class);
        AuthenticatedURL.Token token = new AuthenticatedURL.Token();
        token.set("foo");
        AuthenticatedURL.injectToken(conn, token);
        Mockito.verify(conn).addRequestProperty(Mockito.eq("Cookie"), Mockito.anyString());
    }

    public void testExtractTokenOK() throws Exception {
        HttpURLConnection conn = Mockito.mock(HttpURLConnection.class);

        Mockito.when(conn.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        
        String tokenStr = "foo";
        Map<String, List<String>> headers = new HashMap<String, List<String>>();
        List<String> cookies = new ArrayList<String>();
        cookies.add(AuthenticatedURL.AUTH_COOKIE + "=" + tokenStr);
        headers.put("Set-Cookie", cookies);
        Mockito.when(conn.getHeaderFields()).thenReturn(headers);

        AuthenticatedURL.Token token = new AuthenticatedURL.Token();
        AuthenticatedURL.extractToken(conn, token);

        assertEquals(tokenStr, token.toString());
    }

    public void testExtractTokenFail() throws Exception {
        HttpURLConnection conn = Mockito.mock(HttpURLConnection.class);

        Mockito.when(conn.getResponseCode()).thenReturn(HttpURLConnection.HTTP_UNAUTHORIZED);

        String tokenStr = "foo";
        Map<String, List<String>> headers = new HashMap<String, List<String>>();
        List<String> cookies = new ArrayList<String>();
        cookies.add(AuthenticatedURL.AUTH_COOKIE + "=" + tokenStr);
        headers.put("Set-Cookie", cookies);
        Mockito.when(conn.getHeaderFields()).thenReturn(headers);

        try {
            AuthenticatedURL.extractToken(conn, new AuthenticatedURL.Token());
            fail();
        }
        catch (AuthenticationException ex) {
        }
        catch (Exception ex) {
            fail();
        }
    }

    public void testCaseInsensitiveHeaderExtraction() {
        HttpURLConnection conn = Mockito.mock(HttpURLConnection.class);

        Map<String, List<String>> headers = new HashMap<String, List<String>>();
        headers.put("header", Lists.newArrayList("value 1"));
        headers.put("HEADER", Lists.newArrayList("value 2"));
        headers.put("hEadEr", Lists.newArrayList("value 3"));
        headers.put(null, Lists.newArrayList("value X"));

        Mockito.when(conn.getHeaderFields()).thenReturn(headers);

        List<String> values = AuthenticatedURL.readHeaderField(conn, "headeR");

        assertEquals(values, Lists.newArrayList("value 1", "value 2", "value 3"));
    }

}
