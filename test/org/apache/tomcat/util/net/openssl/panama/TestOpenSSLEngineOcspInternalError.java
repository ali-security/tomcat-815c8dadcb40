/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.util.net.openssl.panama;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.core.OpenSSLLifecycleListener;
import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.net.TesterSupport;

/**
 * Checks the error recorded in the X509_STORE_CTX by the OpenSSL FFM engine
 * when an OCSP request fails because of an internal error or because the OCSP
 * responder is not able to provide a usable response. The verify callback uses
 * that error to decide whether the OCSP check soft-fails so it must always be
 * set and must not be replaced once set.
 * <p>
 * The test sources are compiled for Java 8 so all access to the FFM API and to
 * the FFM based classes is via reflection.
 */
public class TestOpenSSLEngineOcspInternalError {

    private static final String OPENSSL_H = "org.apache.tomcat.util.openssl.openssl_h";
    private static final String ENGINE = "org.apache.tomcat.util.net.openssl.panama.OpenSSLEngine";

    private static final String HOST = "127.0.0.1";

    private static final int OCSP_TIMEOUT = 5000;
    private static final int OCSP_SHORT_TIMEOUT = 1000;

    // OCSPResponse with responseStatus internalError(2) and no responseBytes
    private static final byte[] OCSP_INTERNAL_ERROR_RESPONSE = new byte[] { 0x30, 0x03, 0x0a, 0x01, 0x02 };
    // 64 MiB
    private static final int LARGE_RESPONSE_SIZE = 64 * 1024 * 1024;

    private static Class<?> memorySegmentClass;
    private static Class<?> arenaClass;
    private static Class<?> opensslH;
    private static Object nullSegment;
    private static Object addressLayout;
    private static Object byteLayout;
    private static Object classArena;

    private static MethodHandle x509StoreCtxNew;
    private static MethodHandle x509StoreCtxFree;

    private static int unableToGetCrl;
    private static int applicationVerification;
    private static int certStatusUnknown;

    private static Object leaf;
    private static Object issuer;

    private Object sslCtx;
    private Object engineState;
    private Object x509ctx;
    private TesterRawOcspResponder responder;


    @BeforeClass
    public static void setUp() throws Exception {
        Assume.assumeTrue("FFM requires Java 22 or later", JreCompat.isJre22Available());
        @SuppressWarnings("unused")
        OpenSSLLifecycleListener listener = new OpenSSLLifecycleListener();
        Assume.assumeTrue("OpenSSL is not available", OpenSSLLifecycleListener.isAvailable());

        memorySegmentClass = Class.forName("java.lang.foreign.MemorySegment");
        arenaClass = Class.forName("java.lang.foreign.Arena");
        opensslH = Class.forName(OPENSSL_H);
        nullSegment = memorySegmentClass.getField("NULL").get(null);
        Class<?> valueLayoutClass = Class.forName("java.lang.foreign.ValueLayout");
        addressLayout = valueLayoutClass.getField("ADDRESS").get(null);
        byteLayout = valueLayoutClass.getField("JAVA_BYTE").get(null);
        classArena = arenaClass.getMethod("ofAuto").invoke(null);

        // Functions not exposed by openssl_h
        x509StoreCtxNew = downcall("X509_STORE_CTX_new", addressLayout);
        x509StoreCtxFree = downcall("X509_STORE_CTX_free", null, addressLayout);

        unableToGetCrl = ((Integer) call("X509_V_ERR_UNABLE_TO_GET_CRL")).intValue();
        applicationVerification = ((Integer) call("X509_V_ERR_APPLICATION_VERIFICATION")).intValue();
        certStatusUnknown = ((Integer) call("V_OCSP_CERTSTATUS_UNKNOWN")).intValue();

        // Client certificate and an issuer
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream is = new FileInputStream(new File(TesterSupport.CLIENT_JKS))) {
            ks.load(is, TesterSupport.JKS_PASS.toCharArray());
        }
        Certificate[] chain = ks.getCertificateChain(TesterSupport.CLIENT_ALIAS);
        Assert.assertNotNull(chain);
        Certificate caCertificate;
        try (InputStream is = new FileInputStream(new File(TesterSupport.CA_CERT_PEM))) {
            caCertificate = CertificateFactory.getInstance("X.509").generateCertificate(is);
        }
        leaf = toNativeX509(chain[0]);
        issuer = toNativeX509(caCertificate);
    }


    @AfterClass
    public static void tearDown() throws Exception {
        if (leaf != null) {
            call("X509_free", leaf);
            leaf = null;
        }
        if (issuer != null) {
            call("X509_free", issuer);
            issuer = null;
        }
    }


    @After
    public void releaseResources() throws Throwable {
        if (responder != null) {
            responder.close();
            responder = null;
        }
        if (engineState != null) {
            // Frees the SSL and the BIO
            ((Runnable) engineState).run();
            engineState = null;
        }
        if (sslCtx != null) {
            call("SSL_CTX_free", sslCtx);
            sslCtx = null;
        }
        if (x509ctx != null) {
            x509StoreCtxFree.invokeWithArguments(x509ctx);
            x509ctx = null;
        }
    }


    @Test
    public void testResponderHttpError() throws Throwable {
        responder = new TesterRawOcspResponder(socket -> writeResponse(socket, "500 Internal Server Error", new byte[0]));
        doTestOcspFailure(responder.getUrl(), OCSP_TIMEOUT, unableToGetCrl);
    }


    @Test
    public void testResponderUnavailable() throws Throwable {
        int port;
        try (ServerSocket s = new ServerSocket()) {
            s.bind(new InetSocketAddress(HOST, 0));
            port = s.getLocalPort();
        }
        // Nothing is listening on the port anymore
        doTestOcspFailure(new URL("http://" + HOST + ":" + port + "/"), OCSP_TIMEOUT, unableToGetCrl);
    }


    @Test
    public void testResponderReadTimeout() throws Throwable {
        // Accept the request but never send a response
        responder = new TesterRawOcspResponder(socket -> {
            InputStream is = socket.getInputStream();
            while (is.read() != -1) {
                // Wait for the client to give up
            }
        });
        doTestOcspFailure(responder.getUrl(), OCSP_SHORT_TIMEOUT, unableToGetCrl);
    }


    @Test
    public void testResponderResponseTooLarge() throws Throwable {
        responder = new TesterRawOcspResponder(socket -> {
            OutputStream os = socket.getOutputStream();
            os.write(("HTTP/1.1 200 OK\r\n" + "Content-Type: application/ocsp-response\r\n" + "Content-Length: " +
                    LARGE_RESPONSE_SIZE + "\r\n" + "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
            byte[] chunk = new byte[1024 * 1024];
            for (int written = 0; written < LARGE_RESPONSE_SIZE; written += chunk.length) {
                os.write(chunk);
            }
            os.flush();
        });
        doTestOcspFailure(responder.getUrl(), OCSP_TIMEOUT, unableToGetCrl);
        // The client must stop reading rather than buffer the whole response
        Assert.assertFalse("The whole oversized OCSP response was read", responder.isResponseCompleted());
    }


    @Test
    public void testResponderInternalErrorStatus() throws Throwable {
        responder = new TesterRawOcspResponder(
                socket -> writeResponse(socket, "200 OK", OCSP_INTERNAL_ERROR_RESPONSE));
        doTestOcspFailure(responder.getUrl(), OCSP_TIMEOUT, unableToGetCrl);
    }


    @Test
    public void testResponderInvalidResponse() throws Throwable {
        responder = new TesterRawOcspResponder(socket -> writeResponse(socket, "200 OK",
                "This is not an OCSP response".getBytes(StandardCharsets.ISO_8859_1)));
        doTestOcspFailure(responder.getUrl(), OCSP_TIMEOUT, applicationVerification);
    }


    private void doTestOcspFailure(URL url, int ocspTimeout, int expectedError) throws Throwable {
        createVerificationContext(ocspTimeout);

        Assert.assertEquals(certStatusUnknown, processOCSPRequest(url));
        Assert.assertEquals("Unexpected X509_STORE_CTX error after failed OCSP request", expectedError,
                getError());
    }


    private void createVerificationContext(int ocspTimeout) throws Throwable {
        x509ctx = x509StoreCtxNew.invokeWithArguments();
        Assert.assertNotEquals(nullSegment, x509ctx);
        // A new context has no error set
        Assert.assertEquals(0, getError());

        sslCtx = call("SSL_CTX_new", call("TLS_server_method"));
        Object ssl = call("SSL_new", sslCtx);
        Object networkBIO = call("BIO_new", call("BIO_s_mem"));

        Class<?> engineStateClass = Class.forName(ENGINE + "$EngineState");
        Constructor<?> constructor = engineStateClass.getDeclaredConstructor(memorySegmentClass,
                memorySegmentClass, int.class, boolean.class, int.class, int.class);
        constructor.setAccessible(true);
        engineState = constructor.newInstance(ssl, networkBIO, Integer.valueOf(10), Boolean.FALSE,
                Integer.valueOf(ocspTimeout), Integer.valueOf(0));
    }


    private int processOCSPRequest(URL url) throws Exception {
        Class<?> engineStateClass = Class.forName(ENGINE + "$EngineState");
        Method processOCSPRequest = Class.forName(ENGINE).getDeclaredMethod("processOCSPRequest",
                engineStateClass, URL.class, memorySegmentClass, memorySegmentClass, memorySegmentClass,
                arenaClass);
        processOCSPRequest.setAccessible(true);
        Object localArena = arenaClass.getMethod("ofConfined").invoke(null);
        try {
            return ((Integer) processOCSPRequest.invoke(null, engineState, url, issuer, leaf, x509ctx,
                    localArena)).intValue();
        } finally {
            ((AutoCloseable) localArena).close();
        }
    }


    private int getError() throws Exception {
        return ((Integer) call("X509_STORE_CTX_get_error", x509ctx)).intValue();
    }


    private static void writeResponse(Socket socket, String status, byte[] body) throws IOException {
        OutputStream os = socket.getOutputStream();
        os.write(("HTTP/1.1 " + status + "\r\n" + "Content-Type: application/ocsp-response\r\n" +
                "Content-Length: " + body.length + "\r\n" + "Connection: close\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
        os.write(body);
        os.flush();
    }


    private static Object toNativeX509(Certificate certificate) throws Exception {
        byte[] der = certificate.getEncoded();
        Object derSegment = arenaClass.getMethod("allocateFrom",
                Class.forName("java.lang.foreign.ValueLayout$OfByte"), byte[].class)
                .invoke(classArena, byteLayout, der);
        Object derPointer = arenaClass.getMethod("allocateFrom",
                Class.forName("java.lang.foreign.AddressLayout"), memorySegmentClass)
                .invoke(classArena, addressLayout, derSegment);
        Object x509 = call("d2i_X509", nullSegment, derPointer, Long.valueOf(der.length));
        Assert.assertNotEquals(nullSegment, x509);
        return x509;
    }


    private static Object call(String name, Object... args) throws Exception {
        for (Method method : opensslH.getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == args.length) {
                return method.invoke(null, args);
            }
        }
        throw new NoSuchMethodException(name);
    }


    private static MethodHandle downcall(String symbol, Object returnLayout, Object... argumentLayouts)
            throws Exception {
        Class<?> memoryLayoutClass = Class.forName("java.lang.foreign.MemoryLayout");
        Class<?> functionDescriptorClass = Class.forName("java.lang.foreign.FunctionDescriptor");
        Class<?> linkerClass = Class.forName("java.lang.foreign.Linker");
        Class<?> linkerOptionClass = Class.forName("java.lang.foreign.Linker$Option");

        Object layouts = Array.newInstance(memoryLayoutClass, argumentLayouts.length);
        for (int i = 0; i < argumentLayouts.length; i++) {
            Array.set(layouts, i, argumentLayouts[i]);
        }
        Object descriptor;
        if (returnLayout == null) {
            descriptor = functionDescriptorClass.getMethod("ofVoid", layouts.getClass()).invoke(null, layouts);
        } else {
            descriptor = functionDescriptorClass.getMethod("of", memoryLayoutClass, layouts.getClass())
                    .invoke(null, returnLayout, layouts);
        }

        Method findOrThrow = opensslH.getDeclaredMethod("findOrThrow", String.class);
        findOrThrow.setAccessible(true);
        Object address = findOrThrow.invoke(null, symbol);

        Object linker = linkerClass.getMethod("nativeLinker").invoke(null);
        Object options = Array.newInstance(linkerOptionClass, 0);
        return (MethodHandle) linkerClass.getMethod("downcallHandle", memorySegmentClass, functionDescriptorClass,
                options.getClass()).invoke(linker, address, descriptor, options);
    }


    @FunctionalInterface
    private interface ResponseWriter {
        void write(Socket socket) throws IOException;
    }


    /**
     * Minimal HTTP server that reads one request per connection and then
     * hands the connection to the provided writer to produce the response.
     */
    private static final class TesterRawOcspResponder implements Runnable, AutoCloseable {

        private final ServerSocket serverSocket;
        private final ResponseWriter writer;
        private final List<Socket> sockets = new ArrayList<>();
        private final Thread thread;
        private volatile boolean responseCompleted = false;

        TesterRawOcspResponder(ResponseWriter writer) throws IOException {
            this.writer = writer;
            serverSocket = new ServerSocket();
            serverSocket.bind(new InetSocketAddress(HOST, 0));
            thread = new Thread(this, "TesterRawOcspResponder");
            thread.setDaemon(true);
            thread.start();
        }

        URL getUrl() throws IOException {
            return new URL("http://" + HOST + ":" + serverSocket.getLocalPort() + "/ocsp");
        }

        boolean isResponseCompleted() {
            return responseCompleted;
        }

        @Override
        public void run() {
            while (!serverSocket.isClosed()) {
                Socket socket;
                try {
                    socket = serverSocket.accept();
                } catch (IOException ioe) {
                    return;
                }
                synchronized (sockets) {
                    sockets.add(socket);
                }
                try {
                    readRequest(new BufferedInputStream(socket.getInputStream()));
                    writer.write(socket);
                    responseCompleted = true;
                } catch (IOException ioe) {
                    // The client stopped reading or closed the connection
                } finally {
                    try {
                        socket.close();
                    } catch (IOException ioe) {
                        // Ignore
                    }
                }
            }
        }

        @Override
        public void close() throws Exception {
            serverSocket.close();
            synchronized (sockets) {
                for (Socket socket : sockets) {
                    socket.close();
                }
            }
            thread.join(10000);
        }

        private static void readRequest(InputStream is) throws IOException {
            StringBuilder headers = new StringBuilder();
            int b;
            while ((b = is.read()) != -1) {
                headers.append((char) b);
                int len = headers.length();
                if (len >= 4 && headers.charAt(len - 4) == '\r' && headers.charAt(len - 3) == '\n' &&
                        headers.charAt(len - 2) == '\r' && headers.charAt(len - 1) == '\n') {
                    break;
                }
            }
            int contentLength = 0;
            for (String line : headers.toString().split("\r\n")) {
                int colon = line.indexOf(':');
                if (colon > 0 &&
                        "content-length".equals(line.substring(0, colon).trim().toLowerCase(Locale.ENGLISH))) {
                    contentLength = Integer.parseInt(line.substring(colon + 1).trim());
                }
            }
            for (int i = 0; i < contentLength; i++) {
                if (is.read() == -1) {
                    break;
                }
            }
        }
    }
}
