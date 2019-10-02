package demo.rc.http.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.Security;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.cert.X509Certificate;

import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TLSSocketConnectionFactory extends SSLSocketFactory {

	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
			Security.addProvider(new BouncyCastleProvider());
	}

	public class TLSHandshakeListener implements HandshakeCompletedListener {

		public void handshakeCompleted(HandshakeCompletedEvent event) {
		}
	}

	private SecureRandom _secureRandom = new SecureRandom();

	@Override
	public Socket createSocket(Socket socket, final String host, int port, boolean arg3) throws IOException {
		if (socket == null) {
			socket = new Socket();
		}
		if (!socket.isConnected()) {
			socket.connect(new InetSocketAddress(host, port));
		}

		final TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(socket.getInputStream(),
				socket.getOutputStream(), _secureRandom);
		return _createSSLSocket(host, tlsClientProtocol);

	}

	@Override
	public String[] getDefaultCipherSuites() {
		return null;
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return null;
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
		return null;
	}

	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException {
		return null;
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
			throws IOException, UnknownHostException {
		return null;
	}

	@Override
	public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
			throws IOException {
		return null;
	}

	private SSLSocket _createSSLSocket(final String host, final TlsClientProtocol tlsClientProtocol) {
		return new SSLSocket() {

			@Override
			public InputStream getInputStream() throws IOException {
				return tlsClientProtocol.getInputStream();
			}

			@Override
			public OutputStream getOutputStream() throws IOException {
				return tlsClientProtocol.getOutputStream();
			}

			@Override
			public synchronized void close() throws IOException {
				tlsClientProtocol.close();
			}

			@Override
			public void addHandshakeCompletedListener(HandshakeCompletedListener arg0) {

			}

			@Override
			public boolean getEnableSessionCreation() {
				return false;
			}

			@Override
			public String[] getEnabledCipherSuites() {
				return new String[] { "" };
			}

			@Override
			public String[] getEnabledProtocols() {
				return new String[] { "" };
			}

			@Override
			public boolean getNeedClientAuth() {
				return false;
			}

			@Override
			public SSLSession getSession() {
				return new SSLSession() {

					public int getApplicationBufferSize() {
						return 0;
					}

					public String getCipherSuite() {
						return null;
					}

					public long getCreationTime() {
						return 0;
					}

					public byte[] getId() {
						return null;
					}

					public long getLastAccessedTime() {
						return 0;
					}

					public java.security.cert.Certificate[] getLocalCertificates() {
						return null;
					}

					public Principal getLocalPrincipal() {
						return null;
					}

					public int getPacketBufferSize() {
						return 0;
					}

					public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
						return null;
					}

					public java.security.cert.Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
						return null;
					}

					public String getPeerHost() {
						return null;
					}

					public int getPeerPort() {
						return 0;
					}

					public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
						return null;
					}

					public String getProtocol() {
						return null;
					}

					public SSLSessionContext getSessionContext() {
						return null;
					}

					public Object getValue(String arg0) {
						return null;
					}

					public String[] getValueNames() {
						return null;
					}

					public void invalidate() {
					}

					public boolean isValid() {
						return false;
					}

					public void putValue(String arg0, Object arg1) {
					}

					public void removeValue(String arg0) {
					}
				};
			}

			@Override
			public String[] getSupportedProtocols() {
				return null;
			}

			@Override
			public boolean getUseClientMode() {
				return false;
			}

			@Override
			public boolean getWantClientAuth() {

				return false;
			}

			@Override
			public void removeHandshakeCompletedListener(HandshakeCompletedListener arg0) {

			}

			@Override
			public void setEnableSessionCreation(boolean arg0) {

			}

			@Override
			public void setEnabledCipherSuites(String[] arg0) {

			}

			@Override
			public void setEnabledProtocols(String[] arg0) {

			}

			@Override
			public void setNeedClientAuth(boolean arg0) {

			}

			@Override
			public void setUseClientMode(boolean arg0) {

			}

			@Override
			public void setWantClientAuth(boolean arg0) {

			}

			@Override
			public String[] getSupportedCipherSuites() {
				return null;
			}

			public void startHandshake() throws IOException {
				tlsClientProtocol.connect(new DefaultTlsClient() {

					public TlsAuthentication getAuthentication() throws IOException {
						return new TlsAuthentication() {

							public void notifyServerCertificate(Certificate serverCertificate) throws IOException {
								
							}

							public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
									throws IOException {
								return null;
							}
						};
					}
				});
			}
		};
	}
}